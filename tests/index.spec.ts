import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { CallId } from '@deepseek-ai/dsh-llm'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import { apply, inject, name, Config, type Config as ConfigType } from '../src/index.ts'

let tempDir: string
let auditPath: string
let auditSequence = 0

beforeAll(async () => {
  tempDir = await mkdtemp(join(tmpdir(), 'command-guard-plugin-'))
})

afterAll(async () => {
  // Windows may still hold the audit file handle for a moment after the last
  // queued write; retry the cleanup once instead of failing the suite on it.
  for (const attempt of [0, 1]) {
    try {
      await rm(tempDir, { recursive: true, force: true })
      return
    } catch {
      if (attempt === 1) return
      await new Promise(resolve => setTimeout(resolve, 100))
    }
  }
})

const FULL_CONFIG: ConfigType = {
  extraProtectedPaths: [],
  dedupeTtlMs: 60_000,
  analyzeTimeoutMs: 2000,
  previewTimeoutMs: 2000,
  previewSampleLimit: 10,
  modelCheckTimeoutMs: 5000,
  modelCheckMaxTokens: 300,
  auditLogMaxBytes: 1024 * 1024,
  auditLogRotations: 3,
  sessionDecisionCap: 20,
  pwshPath: 'pwsh',
  enablePrompt: true,
}

interface RecordedEvent {
  type: string
  data: unknown
}

function fakeAgent(records: RecordedEvent[]): Agent {
  return {
    options: { provider: 'deepseek-official', model: 'deepseek-chat' },
    session: {
      id: 'fake-session',
      events: [{ type: 'turn/start' }],
      append: (type: string, data: unknown) => {
        records.push({ type, data })
        return {} as never
      },
    },
  } as unknown as Agent
}

/** A model-check stub whose single answer is the safe confirmation. */
function safeLlm(answer = '{"intent":"yes","assessment":"safe","explanation":"exactly as intended"}') {
  return {
    stream: async function* () {
      yield { type: 'text-delta', index: 0, text: answer }
      yield { type: 'finish', reason: { kind: 'stop' } }
    },
  }
}

const pwshTool = defineTool({
  name: 'pwsh',
  description: 'run one PowerShell command',
  parameters: { command: { type: 'string', required: true } },
  output: {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: value }],
  },
  async execute(args) {
    return args.command ?? ''
  },
})

const bashTool = defineTool({
  name: 'bash',
  description: 'run one bash command',
  parameters: { command: { type: 'string', required: true } },
  output: {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: value }],
  },
  async execute(args) {
    return args.command ?? ''
  },
})

interface SetupOptions {
  mode?: string
  config?: Partial<ConfigType>
  llm?: unknown
  approval?: unknown
}

async function setup(records: RecordedEvent[], options: SetupOptions = {}) {
  void records
  auditSequence += 1
  auditPath = join(tempDir, 'logs', `command-guard-${auditSequence}.log`)
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  ctx.provide('sandboxPolicy', {
    resolve: () => ({ mode: options.mode ?? 'careful-full-access', workspaceRoot: 'C:\\ws' }),
  })
  ctx.provide('llm', options.llm ?? safeLlm())
  if (options.approval !== undefined) ctx.provide('approval', options.approval)
  await ctx.plugin({ name, inject, apply }, { ...FULL_CONFIG, auditLogPath: auditPath, ...options.config })
  ctx.tools.register(pwshTool)
  ctx.tools.register(bashTool)
  return ctx
}

/** The model-facing text of a settled result's first content block, if any. */
function resultText(result: { content: readonly unknown[] }): string {
  const block = result.content[0] as { text?: unknown } | undefined
  return typeof block?.text === 'string' ? block.text : ''
}

async function execute(ctx: Context, records: RecordedEvent[], command: string, callId = CallId('c1')) {
  return ctx.tools.execute({
    callId, name: 'pwsh', arguments: { command }, agent: fakeAgent(records), signal: new AbortController().signal,
  })
}

/** Read the audit file once it has settled (writes ride an internal queue). */
async function auditLines(): Promise<unknown[]> {
  const raw = await readFile(auditPath, 'utf8')
  return raw.trim().split('\n').map(line => JSON.parse(line))
}

describe('command-guard plugin', () => {
  it('exposes the loader contract and schema defaults', () => {
    expect(name).toBe('command-guard')
    expect(inject).toEqual(['tools'])
    const defaults = Config({})
    expect(defaults.dedupeTtlMs).toBe(600_000)
    expect(defaults.analyzeTimeoutMs).toBe(15_000)
    expect(defaults.modelCheckTimeoutMs).toBe(20_000)
    expect(defaults.modelCheckMaxTokens).toBe(300)
    expect(defaults.auditLogMaxBytes).toBe(5 * 1024 * 1024)
    expect(defaults.auditLogRotations).toBe(3)
    expect(defaults.sessionDecisionCap).toBe(20)
    expect(defaults.extraProtectedPaths).toEqual([])
    expect('confirmTtlMs' in defaults).toBe(false)
  })

  it('lets ordinary careful-mode commands through and audits the allow', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await execute(ctx, records, 'Get-ChildItem C:\\ws')
    expect(result.isError).toBe(false)
    expect(records).toHaveLength(1)
    expect(records[0]?.data).toMatchObject({ toolName: 'pwsh', decision: 'allow' })
  })

  it('passes every other sandbox mode through without guard work or audit', async () => {
    for (const mode of ['workspace-write', 'danger-full-access']) {
      const records: RecordedEvent[] = []
      const ctx = await setup(records, { mode })
      const result = await execute(ctx, records, 'Remove-Item -Recurse -Force C:\\')
      expect(result.isError).toBe(false)
      expect(records).toHaveLength(0)
    }
  })

  it('routes a disaster-tier command to a danger-marked human confirmation when the model confirms it', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await execute(ctx, records, 'Format-Volume D')
    // Without an approval seam the ask degrades to a deny carrying the guard's
    // own confirmation text.
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('风险级别：灾难级')
    expect(records).toHaveLength(1)
    expect(records[0]?.type).toBe('command-guard/decision')
    expect(records[0]?.data).toMatchObject({
      toolName: 'pwsh', decision: 'ask', tier: 'disaster', modelCheck: 'safe', mode: 'careful-full-access',
    })
  })

  it('denies outright when the model disowns the command', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records, {
      llm: safeLlm('{"intent":"no","assessment":"dangerous","explanation":"misparsed path"}'),
    })
    const result = await execute(ctx, records, 'Format-Volume D')
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('not the intended one')
    expect(records.at(-1)?.data).toMatchObject({ decision: 'deny', modelCheck: 'not-intended' })
  })

  it('lets an elevated command the model confirms safe run and audits it', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await execute(ctx, records, 'Clear-RecycleBin -Force')
    expect(result.isError).toBe(false)
    expect(records.at(-1)?.data).toMatchObject({ decision: 'allow', tier: 'elevated', modelCheck: 'safe' })
  })

  it('lets git rm --cached through as a normal command', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await execute(ctx, records, 'git rm -r --cached src')
    expect(result.isError).toBe(false)
    expect(records.at(-1)?.data).toMatchObject({ decision: 'allow' })
  })

  it('ignores non-shell tool calls', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const other = defineTool({
      name: 'web_search',
      description: 'search',
      parameters: { query: { type: 'string', required: true } },
      output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
      async execute(args) { return args.query ?? '' },
    })
    ctx.tools.register(other)
    const result = await ctx.tools.execute({
      callId: CallId('c2'), name: 'web_search', arguments: { query: 'rm -rf /' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(false)
    expect(records).toHaveLength(0)
  })

  it('registers the deletion-discipline prompt section', async () => {
    const ctx = await setup([])
    const assembly = await ctx.systemPrompt.assemble()
    expect(JSON.stringify(assembly)).toContain('Deletion discipline (enforced by the command guard')
    expect(JSON.stringify(assembly)).toContain('model-check')
  })

  it('lets shell calls without a command argument through without audit', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await ctx.tools.execute({
      callId: CallId('c3'), name: 'pwsh', arguments: {}, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(records).toHaveLength(0)
  })

  it('passes agentless executions through without audit', async () => {
    const ctx = await setup([])
    const result = await ctx.tools.execute({
      callId: CallId('c4'), name: 'pwsh', arguments: { command: 'Format-Volume D' }, signal: new AbortController().signal,
    })
    expect(result.isError).toBe(false)
  })

  it('keeps the decision when the session audit append fails', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const throwingAgent = {
      session: {
        id: 'throwing-session',
        events: [{ type: 'turn/start' }],
        append: () => { throw new Error('audit store down') },
      },
    } as unknown as Agent
    const result = await ctx.tools.execute({
      callId: CallId('c5'), name: 'pwsh', arguments: { command: 'Format-Volume D' }, agent: throwingAgent, signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('风险级别：灾难级')
  })

  it('omits the prompt section when enablePrompt is false', async () => {
    const ctx = await setup([], { config: { enablePrompt: false } })
    const assembly = await ctx.systemPrompt.assemble()
    expect(JSON.stringify(assembly)).not.toContain('Deletion discipline')
  })

  it('applies config defaults when mounted without config', async () => {
    vi.stubEnv('DSH_HOME', join(tempDir, 'default-home'))
    try {
      const records: RecordedEvent[] = []
      const ctx = new Context()
      await ctx.plugin(SystemPrompt)
      await ctx.plugin(ToolRuntime)
      ctx.provide('sandboxPolicy', { resolve: () => ({ mode: 'careful-full-access', workspaceRoot: 'C:\\ws' }) })
      ctx.provide('llm', safeLlm())
      await ctx.plugin({ name, inject, apply }, {})
      ctx.tools.register(pwshTool)
      const result = await ctx.tools.execute({
        callId: CallId('c6'), name: 'pwsh', arguments: { command: 'Get-ChildItem C:\\ws' }, agent: fakeAgent(records), signal: new AbortController().signal,
      })
      expect(result.isError).toBe(false)
      expect(records).toHaveLength(1)
    } finally {
      vi.unstubAllEnvs()
    }
  })

  // The red severity chain is a CORE change (patches/careful-full-access.patch):
  // it only forwards when the harness tree carries the patched tools/approval
  // packages. Against published DSH types the ask still works, but stays
  // unmarked — so this assertion runs only in a patched tree.
  it.skipIf(process.env.DSH_GUARD_CORE_PATCH !== '1')('passes the danger severity through the approval seam', async () => {
    const requests: Array<Record<string, unknown>> = []
    const records: RecordedEvent[] = []
    const ctx = await setup(records, {
      approval: {
        request: async (req: Record<string, unknown>) => {
          requests.push(req)
          return 'rejected'
        },
      },
    })
    const result = await execute(ctx, records, 'Format-Volume D')
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('the user rejected tool "pwsh"')
    expect(requests).toHaveLength(1)
    expect(requests[0]).toMatchObject({
      toolName: 'pwsh', severity: 'danger',
      reason: expect.stringContaining('准备执行："Format-Volume D"'),
    })
  })

  it('writes the complete decision trail to the rotated file log', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    await execute(ctx, records, 'Format-Volume D')
    const lines = await vi.waitFor(async () => {
      const entries = await auditLines()
      expect(entries.length).toBeGreaterThan(0)
      return entries
    })
    expect(lines.at(-1)).toMatchObject({
      toolName: 'pwsh', decision: 'ask', tier: 'disaster', mode: 'careful-full-access', count: 1,
    })
  })

  it('merges identical commands into one session event with a repeat marker line', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    await execute(ctx, records, 'Format-Volume D', CallId('c7'))
    await execute(ctx, records, 'Format-Volume D', CallId('c8'))
    expect(records.filter(record => record.type === 'command-guard/decision')).toHaveLength(1)
    const lines = await vi.waitFor(async () => {
      const entries = await auditLines()
      expect(entries.length).toBe(2)
      return entries
    })
    expect(lines[0]).toMatchObject({ decision: 'ask', count: 1 })
    expect(lines[1]).toMatchObject({ event: 'repeat', count: 2 })
  })

  it('caps the session decision events at the configured limit', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records, { config: { sessionDecisionCap: 3 } })
    for (let index = 0; index < 5; index += 1) {
      await execute(ctx, records, `Format-Volume D${index}`, CallId(`cap-${index}`))
    }
    expect(records.filter(record => record.type === 'command-guard/decision')).toHaveLength(3)
  })

  it('asks without a danger marking when an elevated command is model-declared dangerous', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records, {
      llm: safeLlm('{"intent":"yes","assessment":"dangerous","explanation":"wildcard escapes"}'),
    })
    const result = await execute(ctx, records, 'Clear-RecycleBin -Force')
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('模型复核认为此操作有危险')
    expect(records.at(-1)?.data).toMatchObject({ decision: 'ask', tier: 'elevated', modelCheck: 'dangerous' })
  })

  it('judges the bash dialect through the same route', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await ctx.tools.execute({
      callId: CallId('c-bash-1'), name: 'bash', arguments: { command: 'rm -rf /' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('风险级别：灾难级')
    expect(records.at(-1)?.data).toMatchObject({ toolName: 'bash', decision: 'ask', tier: 'disaster' })
  })

  it('formats a non-Error audit failure into the warning', async () => {
    const ctx = await setup([])
    const throwingAgent = {
      session: {
        id: 'throwing-session-2',
        events: [{ type: 'turn/start' }],
        append: () => { throw 'plain string failure' },
      },
    } as unknown as Agent
    const result = await ctx.tools.execute({
      callId: CallId('c9'), name: 'pwsh', arguments: { command: 'Format-Volume D' }, agent: throwingAgent, signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
  })
})
