import { describe, expect, it, vi } from 'vitest'
import type { PwshAnalyzer } from '../src/analyzer.ts'
import { GuardEngine } from '../src/engine.ts'
import type { ModelCheckOutcome, ModelCheckRunner } from '../src/model-check.ts'
import type { PreviewRunner } from '../src/preview.ts'
import { buildProtectedRoots } from '../src/protected.ts'
import type { PreviewOutcome, PwshReport } from '../src/types.ts'

const ROOTS = buildProtectedRoots([], { USERPROFILE: 'C:\\Users\\me', SystemRoot: 'C:\\Windows' })

function okReport(): PwshReport {
  return { ok: true, aborted: false, parseErrors: 0, commands: [], memberCalls: [] }
}

function engineWith(overrides: {
  analyze?: (command: string) => Promise<PwshReport>
  preview?: (command: string) => Promise<PreviewOutcome>
  check?: () => Promise<ModelCheckOutcome>
} = {}) {
  const analyzer = { analyze: vi.fn(async (command: string) => overrides.analyze?.(command) ?? okReport()) } as unknown as PwshAnalyzer
  const preview = {
    preview: vi.fn(async (command: string) => overrides.preview?.(command) ?? { kind: 'unpreviewable', detail: 'no fake' } as PreviewOutcome),
  } as unknown as PreviewRunner
  const modelCheck = {
    check: vi.fn(async () => overrides.check?.() ?? { kind: 'safe' } as ModelCheckOutcome),
  } as unknown as ModelCheckRunner
  const engine = new GuardEngine({ analyzer, preview, protectedRoots: ROOTS, modelCheck })
  return { engine, analyzer, preview, modelCheck }
}

function pwsh(command: string, mode: Parameters<GuardEngine['judge']>[0]['mode'] = 'careful-full-access', workspaceRoot = 'C:\\ws') {
  return {
    dialect: 'pwsh' as const, command, mode, workspaceRoot, sessionKey: 's1',
    route: { provider: 'deepseek-official', model: 'deepseek-chat' } as const,
  }
}

describe('GuardEngine mode gating', () => {
  it('never judges anything outside careful-full-access', async () => {
    const { engine, analyzer, modelCheck } = engineWith()
    for (const mode of ['workspace-write', 'danger-full-access'] as const) {
      expect(await engine.judge(pwsh('Remove-Item -Recurse -Force C:\\', mode))).toEqual({ kind: 'allow' })
      expect(await engine.judge(pwsh('Remove-Item C:\\ws\\a.txt', mode))).toEqual({ kind: 'allow' })
    }
    expect(analyzer.analyze).not.toHaveBeenCalled()
    expect(modelCheck.check).not.toHaveBeenCalled()
  })

  it('allows non-destructive commands without spawning the analyzer', async () => {
    const { engine, analyzer } = engineWith()
    expect(await engine.judge(pwsh('Get-ChildItem C:\\ws'))).toEqual({ kind: 'allow' })
    expect(analyzer.analyze).not.toHaveBeenCalled()
  })

  it('judges without a workspace root', async () => {
    const { engine } = engineWith()
    expect(await engine.judge({ ...pwsh('Get-ChildItem C:\\ws'), workspaceRoot: undefined })).toEqual({ kind: 'allow' })
  })

  it('routes a normal-tier destructive signal straight through without review', async () => {
    const { engine, modelCheck } = engineWith()
    const decision = await engine.judge(pwsh('[System.IO.File]::Delete("C:\\ws\\x.txt")'))
    expect(decision).toEqual({ kind: 'allow' })
    expect(modelCheck.check).not.toHaveBeenCalled()
  })
})

describe('GuardEngine pwsh review route', () => {
  it('routes lex-proven disaster commands to the model check without an analyzer spawn', async () => {
    const { engine, analyzer, modelCheck } = engineWith({ check: async () => ({ kind: 'safe' }) })
    const decision = await engine.judge(pwsh('Remove-Item -Recurse -Force C:\\'))
    expect(decision).toMatchObject({ kind: 'ask', severity: 'danger' })
    expect(analyzer.analyze).not.toHaveBeenCalled()
    expect(modelCheck.check).toHaveBeenCalledWith(expect.objectContaining({ tier: 'disaster', command: 'Remove-Item -Recurse -Force C:\\' }))
  })

  it('allows an elevated command the model confirms as intended and safe', async () => {
    const { engine } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'Remove-Item', strings: ['C:\\ws\\old.txt'], expandables: [], variables: [], parameters: [] }],
      }),
      preview: async () => ({ kind: 'previewed', objectCount: 1, fileCount: 1, directoryCount: 0, samples: ['C:\\ws\\old.txt'], truncated: false }),
    })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\old.txt'))
    expect(decision).toEqual({ kind: 'allow', tier: 'elevated', modelCheck: 'safe' })
  })

  it('denies when the model disowns the command', async () => {
    const { engine } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'Remove-Item', strings: ['C:\\ws\\old.txt'], expandables: [], variables: [], parameters: [] }],
      }),
      check: async () => ({ kind: 'not-intended', explanation: 'the path came out of a misparsed variable' }),
    })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\old.txt'))
    expect(decision.kind).toBe('deny')
    expect(decision.kind === 'deny' && decision.modelCheck).toBe('not-intended')
    expect(decision.kind === 'deny' && decision.reason).toContain('not the intended one')
  })

  it('escalates a model-declared-dangerous elevated command to an ordinary ask', async () => {
    const { engine } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'Remove-Item', strings: ['C:\\ws\\*.bak'], expandables: [], variables: [], parameters: ['Recurse', 'Force'] }],
      }),
      preview: async () => ({
        kind: 'previewed', objectCount: 3, fileCount: 2, directoryCount: 1,
        samples: ['C:\\ws\\old', 'C:\\ws\\old\\a.bak', 'C:\\ws\\old\\b.bak'], truncated: false,
      }),
      check: async () => ({ kind: 'dangerous', explanation: 'the wildcard reaches beyond the expected folder' }),
    })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\*.bak -Recurse -Force'))
    expect(decision).toMatchObject({ kind: 'ask', modelCheck: 'dangerous' })
    expect(decision.kind === 'ask' && decision.severity).toBeUndefined()
    expect(decision.kind === 'ask' && decision.reason).toContain('准备执行："Remove-Item C:\\\\ws\\\\*.bak -Recurse -Force"')
    expect(decision.kind === 'ask' && decision.reason).toContain('操作说明：递归删除指定目标及其子项')
    expect(decision.kind === 'ask' && decision.reason).toContain('WhatIf 预演解析出 3 个对象（2 个文件、1 个目录）')
    expect(decision.kind === 'ask' && decision.reason).toContain('完整目标清单："C:\\\\ws\\\\old"、"C:\\\\ws\\\\old\\\\a.bak"、"C:\\\\ws\\\\old\\\\b.bak"')
    expect(decision.kind === 'ask' && decision.reason).toContain('风险级别：高风险')
    expect(decision.kind === 'ask' && decision.reason).toContain('模型复核认为此操作有危险')
  })

  it('escalates a dangerous disaster-tier command with the danger severity', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'dangerous', explanation: 'this wipes the whole drive' }) })
    const decision = await engine.judge(pwsh('Remove-Item -Recurse -Force C:\\'))
    expect(decision).toMatchObject({ kind: 'ask', severity: 'danger', modelCheck: 'dangerous' })
  })

  it('keeps disaster commands un-auto-allowed even when the model confirms them safe', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'safe' }) })
    const decision = await engine.judge(pwsh('Remove-Item -Recurse -Force C:\\'))
    expect(decision).toMatchObject({ kind: 'ask', severity: 'danger', modelCheck: 'safe' })
    expect(decision.kind === 'ask' && decision.reason).toContain('风险级别：灾难级')
    expect(decision.kind === 'ask' && decision.reason).toContain('模型复核认为命令符合原意')
  })

  it('treats a failed analysis as unparseable: human confirmation even on a safe review', async () => {
    const { engine } = engineWith({
      analyze: async () => ({ ok: false, aborted: false, parseErrors: -1, commands: [], memberCalls: [] }),
    })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\x'))
    expect(decision).toMatchObject({ kind: 'ask', severity: 'danger' })
    expect(decision.kind === 'ask' && decision.reason).toContain('风险级别：无法可靠解析（按灾难级处理）')
  })

  it('fails closed when the model check is unavailable', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'unavailable', detail: 'no model route available' }) })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\a.txt'))
    expect(decision).toMatchObject({ kind: 'ask', severity: 'danger', modelCheck: 'unavailable' })
    expect(decision.kind === 'ask' && decision.reason).toContain('模型复核不可用，无法确认安全性')
  })

  it('allows zero-target previews without a model-check call', async () => {
    const { engine, modelCheck } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'Remove-Item', strings: ['C:\\ws\\gone.txt'], expandables: [], variables: [], parameters: [] }],
      }),
      preview: async () => ({ kind: 'zero-targets' }),
    })
    expect(await engine.judge(pwsh('Remove-Item C:\\ws\\gone.txt'))).toEqual({ kind: 'allow', tier: 'elevated' })
    expect(modelCheck.check).not.toHaveBeenCalled()
  })

  it('upgrades a preview-resolved protected root to a danger-marked ask', async () => {
    const { engine } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'Remove-Item', strings: ['C:\\ws\\link*'], expandables: [], variables: [], parameters: ['Recurse'] }],
      }),
      preview: async () => ({ kind: 'protected-hit', target: 'D:\\' }),
    })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\link* -Recurse'))
    expect(decision).toMatchObject({ kind: 'ask', severity: 'danger' })
    expect(decision.kind === 'ask' && decision.reason).toContain('WhatIf 预演解析到受保护根目录 "D:\\\\"')
  })

  it('states that an unresolved preview does not prove an empty deletion scope', async () => {
    const { engine } = engineWith({
      check: async () => ({ kind: 'safe' }),
      preview: async () => ({ kind: 'unpreviewable', detail: 'timeout' }),
    })
    const decision = await engine.judge(pwsh('Remove-Item -Recurse -Force C:\\'))
    expect(decision.kind === 'ask' && decision.reason).toContain('无法准确列出实际文件；缺少清单不表示命令不会删除文件')
  })

  it('labels a truncated preview list as partial', async () => {
    const { engine } = engineWith({
      preview: async () => ({
        kind: 'previewed', objectCount: 20, fileCount: 20, directoryCount: 0,
        samples: ['C:\\ws\\a.txt', 'C:\\ws\\b.txt'], truncated: true,
      }),
      check: async () => ({ kind: 'dangerous', explanation: 'batch delete' }),
    })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\*.txt'))
    expect(decision.kind === 'ask' && decision.reason).toContain('目标清单仅显示前 2 个')
    expect(decision.kind === 'ask' && decision.reason).toContain('其余对象未显示')
  })

  it('does not invent target names when a preview returns counts only', async () => {
    const { engine } = engineWith({
      preview: async () => ({ kind: 'previewed', objectCount: 1, fileCount: 1, directoryCount: 0, samples: [], truncated: false }),
      check: async () => ({ kind: 'dangerous', explanation: 'unknown name' }),
    })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\x.txt'))
    expect(decision.kind === 'ask' && decision.reason).toContain('预演没有返回可显示的目标名称')
  })

  it('explains disk formatting without claiming a per-file preview', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'safe' }) })
    const decision = await engine.judge(pwsh('Format-Volume D'))
    expect(decision.kind === 'ask' && decision.reason).toContain('格式化或清空存储设备，其中的数据可能全部丢失')
    expect(decision.kind === 'ask' && decision.reason).toContain('无法按普通文件删除逐项预览')
  })

  it('never previews non-delete elevated commands', async () => {
    const { engine, preview } = engineWith()
    const decision = await engine.judge(pwsh('Clear-RecycleBin -Force'))
    expect(decision).toEqual({ kind: 'allow', tier: 'elevated', modelCheck: 'safe' })
    expect(preview.preview).not.toHaveBeenCalled()
  })

  it('classifies destructive git subcommands without an analyzer spawn', async () => {
    const { engine, analyzer } = engineWith()
    const decision = await engine.judge(pwsh('git clean -fd'))
    expect(decision).toEqual({ kind: 'allow', tier: 'elevated', modelCheck: 'safe' })
    expect(analyzer.analyze).not.toHaveBeenCalled()
  })

  it.each([
    ['git clean -fd', '删除 Git 工作区中未跟踪的文件和目录'],
    ['git reset --hard HEAD', '用仓库版本覆盖 Git 工作区文件，未提交的修改会丢失'],
    ['git rm tracked.txt', '从 Git 索引和工作区删除已跟踪的文件'],
  ])('explains the destructive effect of %s', async (command, explanation) => {
    const { engine } = engineWith({ check: async () => ({ kind: 'dangerous', explanation: 'destructive git operation' }) })
    const decision = await engine.judge(pwsh(command))
    expect(decision.kind === 'ask' && decision.reason).toContain(`操作说明：${explanation}`)
  })

  it('explains a protected-root robocopy mirror as destructive synchronization', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'safe' }) })
    const decision = await engine.judge(pwsh('robocopy C:\\source C:\\ /MIR'))
    expect(decision.kind === 'ask' && decision.reason).toContain('执行镜像同步，并删除目标端中源目录不存在的内容')
  })

  it('uses a conservative generic explanation for opaque dynamic execution', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'safe' }) })
    const decision = await engine.judge(pwsh('iex $script'))
    expect(decision.kind === 'ask' && decision.reason).toContain('执行可能删除或覆盖数据的高风险操作')
  })

  it('states when a PowerShell deletion has no statically confirmed path', async () => {
    const { engine } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'noop', strings: ['C:\\Users\\me\\x'], expandables: [], variables: [], parameters: [] }],
        memberCalls: ['Directory'],
      }),
      check: async () => ({ kind: 'dangerous', explanation: 'direct .NET delete' }),
    })
    const decision = await engine.judge(pwsh('[System.IO.Directory]::Delete("C:\\Users\\me\\x", $true)'))
    expect(decision.kind === 'ask' && decision.reason).toContain('没有取得可验证的逐文件清单；命令中没有可静态确认的目标路径')
  })

  it('lets git rm --cached through as a normal command', async () => {
    const { engine, modelCheck } = engineWith()
    expect(await engine.judge(pwsh('git rm -r --cached src'))).toEqual({ kind: 'allow' })
    expect(modelCheck.check).not.toHaveBeenCalled()
  })
})

describe('GuardEngine bash', () => {
  function bash(command: string, mode: Parameters<GuardEngine['judge']>[0]['mode'] = 'careful-full-access') {
    return {
      dialect: 'bash' as const, command, mode, workspaceRoot: '/ws', sessionKey: 's1',
      route: { provider: 'deepseek-official', model: 'deepseek-chat' } as const,
    }
  }

  it('allows non-destructive bash commands without any analysis', async () => {
    const { engine } = engineWith()
    expect(await engine.judge(bash('ls -la /tmp'))).toEqual({ kind: 'allow' })
  })

  it('routes recursive deletion of the POSIX root to a danger-marked ask', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'safe' }) })
    const decision = await engine.judge(bash('rm -rf /'))
    expect(decision).toMatchObject({ kind: 'ask', severity: 'danger' })
    expect(decision.kind === 'ask' && decision.reason).toContain('Bash 删除命令没有 WhatIf 预演')
    expect(decision.kind === 'ask' && decision.reason).toContain('命令中的目标表达式："/"')
  })

  it('allows an elevated bash deletion the model confirms safe', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'safe' }) })
    expect(await engine.judge(bash('rm /ws/old.txt'))).toEqual({ kind: 'allow', tier: 'elevated', modelCheck: 'safe' })
  })

  it('denies when the model disowns a bash deletion', async () => {
    const { engine } = engineWith({ check: async () => ({ kind: 'not-intended', explanation: 'wrong target' }) })
    const decision = await engine.judge(bash('rm -rf "$HOME/docs"'))
    expect(decision.kind).toBe('deny')
  })

  it('has no preview pipeline on bash (documented degradation)', async () => {
    const { engine, preview } = engineWith({ check: async () => ({ kind: 'safe' }) })
    const decision = await engine.judge(bash('rm -rf /outside -f'))
    expect(decision).toEqual({ kind: 'allow', tier: 'elevated', modelCheck: 'safe' })
    expect(preview.preview).not.toHaveBeenCalled()
  })
})
