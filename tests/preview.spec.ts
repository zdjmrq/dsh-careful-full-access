import { describe, expect, it } from 'vitest'
import { PreviewRunner, parseEnumeration, parseWhatIfLines, previewDenyReason, renderPreviewSummary } from '../src/preview.ts'
import { buildProtectedRoots } from '../src/protected.ts'
import type { SpawnResult } from '../src/types.ts'

const ROOTS = buildProtectedRoots([], { USERPROFILE: 'C:\\Users\\me', SystemRoot: 'C:\\Windows' })

const WHATIF_OUTPUT = [
  'What if: Performing the operation "Remove File" on target "C:\\ws\\a.txt".',
  'What if: Performing the operation "Remove Directory" on target "C:\\ws\\sub".',
].join('\n')

const ZH_WHATIF_OUTPUT = '假设: 正在目标“C:\\ws\\a.txt”上执行操作“Remove File”。'

const ENUM_JSON = JSON.stringify([
  { path: 'C:\\ws\\sub', files: 2, dirs: 1, samples: ['C:\\ws\\sub\\b.txt'], truncated: false },
])

describe('parseWhatIfLines', () => {
  it('parses the English WhatIf line format', () => {
    const targets = parseWhatIfLines(WHATIF_OUTPUT)
    expect(targets).toEqual([
      { op: 'Remove File', target: 'C:\\ws\\a.txt' },
      { op: 'Remove Directory', target: 'C:\\ws\\sub' },
    ])
  })

  it('parses the zh-CN localized prefix', () => {
    const targets = parseWhatIfLines(ZH_WHATIF_OUTPUT)
    expect(targets).toEqual([{ op: 'Remove File', target: 'C:\\ws\\a.txt' }])
  })

  it('ignores unrelated lines', () => {
    expect(parseWhatIfLines('noise\nother noise')).toEqual([])
  })
})

describe('parseEnumeration', () => {
  it('parses valid enumeration output', () => {
    const subtrees = parseEnumeration(ENUM_JSON)
    expect(subtrees).toEqual([
      { path: 'C:\\ws\\sub', files: 2, dirs: 1, samples: ['C:\\ws\\sub\\b.txt'], truncated: false },
    ])
  })

  it('fails closed on unreadable output', () => {
    expect(parseEnumeration('')).toBeUndefined()
    expect(parseEnumeration('not json')).toBeUndefined()
    expect(parseEnumeration('{"a":1}')).toBeUndefined()
  })

  it('drops malformed entries and keeps missing markers', () => {
    const subtrees = parseEnumeration(JSON.stringify([
      { path: 'D:\\x', files: 1, dirs: 0, samples: [], truncated: false },
      { bad: true },
      null,
      'string entry',
      { path: 'D:\\gone', files: -1, dirs: -1, samples: [], truncated: false, missing: true },
    ]))
    if (subtrees === undefined) throw new Error('parseEnumeration unexpectedly failed')
    expect(subtrees).toHaveLength(2)
    expect(subtrees[1]?.missing).toBe(true)
  })
})

describe('renderPreviewSummary', () => {
  it('renders counts, samples, and the scope-verification instruction', () => {
    const text = renderPreviewSummary(2, 1, ['C:\\ws\\sub\\b.txt'], false)
    expect(text).toContain('3 objects (2 files, 1 directories)')
    expect(text).toContain('"C:\\ws\\sub\\b.txt"')
    expect(text).toContain('verify this scope matches your intent')
  })

  it('renders the empty-sample form and truncation marker', () => {
    const text = renderPreviewSummary(5, 0, [], true)
    expect(text).toContain('5 objects (5 files, 0 directories)')
    expect(text).not.toContain('first targets')
  })

  it('marks sample truncation inside the summary', () => {
    const text = renderPreviewSummary(1, 0, ['C:\\a.txt'], true)
    expect(text).toContain('"C:\\a.txt", …')
  })

  it('previewDenyReason reuses the summary text', () => {
    const reason = previewDenyReason({ kind: 'previewed', objectCount: 1, fileCount: 1, directoryCount: 0, samples: ['a'], truncated: false })
    expect(reason).toContain('verify this scope matches your intent')
  })
})

describe('PreviewRunner', () => {
  function runnerWith(script: (argv: string[]) => Promise<SpawnResult>, sampleLimit = 10) {
    const calls: string[][] = []
    const runner = new PreviewRunner(
      async (argv, options) => {
        calls.push(argv)
        void options
        return await script(argv)
      },
      { timeoutMs: 1000, sampleLimit, pwshPath: 'pwsh' },
      ROOTS,
    )
    return { runner, calls }
  }

  it('returns zero-targets when the dry run deletes nothing', async () => {
    const { runner } = runnerWith(async () => ({ stdout: '', stderr: '', exitCode: 0, timedOut: false }))
    expect(await runner.preview('Remove-Item C:\\ws\\nothing.txt')).toEqual({ kind: 'zero-targets' })
  })

  it('refuses when a resolved target is a protected root', async () => {
    const { runner } = runnerWith(async () => ({
      stdout: 'What if: Performing the operation "Remove Directory" on target "D:\\".',
      stderr: '', exitCode: 0, timedOut: false,
    }))
    expect(await runner.preview('Remove-Item D:\\ -Recurse -Force')).toEqual({ kind: 'protected-hit', target: 'D:\\' })
  })

  it('fails closed on dry-run spawn failures, timeouts, and non-zero exits without targets', async () => {
    const cases: SpawnResult[] = [
      { stdout: '', stderr: '', exitCode: null, timedOut: false, spawnError: 'boom' },
      { stdout: '', stderr: '', exitCode: null, timedOut: true },
      { stdout: '', stderr: 'err', exitCode: 1, timedOut: false },
    ]
    for (const result of cases) {
      const { runner } = runnerWith(async () => result)
      const outcome = await runner.preview('Remove-Item C:\\ws\\x')
      expect(outcome.kind).toBe('unpreviewable')
    }
  })

  it('previews file-only deletions without an enumeration spawn', async () => {
    const { runner, calls } = runnerWith(async () => ({
      stdout: 'What if: Performing the operation "Remove File" on target "C:\\ws\\a.txt".',
      stderr: '', exitCode: 0, timedOut: false,
    }))
    const outcome = await runner.preview('Remove-Item C:\\ws\\a.txt')
    expect(outcome).toMatchObject({ kind: 'previewed', objectCount: 1, fileCount: 1, directoryCount: 0 })
    expect(calls).toHaveLength(1)
  })

  it('enumerates resolved directory targets and merges counts', async () => {
    const { runner } = runnerWith(async (argv) => {
      const encoded = argv.includes('-EncodedCommand') && argv[argv.indexOf('-EncodedCommand') + 1] !== undefined
        ? argv[argv.indexOf('-EncodedCommand') + 1]!
        : ''
      const script = Buffer.from(encoded, 'base64').toString('utf16le')
      if (script.includes('$WhatIfPreference')) {
        return { stdout: 'What if: Performing the operation "Remove Directory" on target "C:\\ws\\sub".', stderr: '', exitCode: 0, timedOut: false }
      }
      return { stdout: ENUM_JSON, stderr: '', exitCode: 0, timedOut: false }
    })
    const outcome = await runner.preview('Remove-Item C:\\ws\\sub -Recurse')
    expect(outcome).toMatchObject({ kind: 'previewed', fileCount: 2, directoryCount: 2, objectCount: 4 })
    expect(outcome.kind === 'previewed' && outcome.samples).toContain('C:\\ws\\sub\\b.txt')
  })

  it('fails closed when the enumeration cannot complete', async () => {
    const { runner } = runnerWith(async (argv) => {
      const encoded = argv.includes('-EncodedCommand') ? argv[argv.indexOf('-EncodedCommand') + 1]! : ''
      const script = Buffer.from(encoded, 'base64').toString('utf16le')
      if (script.includes('$WhatIfPreference')) {
        return { stdout: 'What if: Performing the operation "Remove Directory" on target "C:\\ws\\sub".', stderr: '', exitCode: 0, timedOut: false }
      }
      return { stdout: '', stderr: '', exitCode: 1, timedOut: false }
    })
    const outcome = await runner.preview('Remove-Item C:\\ws\\sub -Recurse')
    expect(outcome.kind).toBe('unpreviewable')
  })

  it('fails closed when the enumeration output is unreadable', async () => {
    const { runner } = runnerWith(async (argv) => {
      const encoded = argv.includes('-EncodedCommand') ? argv[argv.indexOf('-EncodedCommand') + 1]! : ''
      const script = Buffer.from(encoded, 'base64').toString('utf16le')
      if (script.includes('$WhatIfPreference')) {
        return { stdout: 'What if: Performing the operation "Remove Directory" on target "C:\\ws\\sub".', stderr: '', exitCode: 0, timedOut: false }
      }
      return { stdout: 'garbage not json', stderr: '', exitCode: 0, timedOut: false }
    })
    const outcome = await runner.preview('Remove-Item C:\\ws\\sub -Recurse')
    expect(outcome).toEqual({ kind: 'unpreviewable', detail: 'the subtree enumeration produced unreadable output' })
  })

  it('skips missing subtrees, caps samples, and marks truncation', async () => {
    const manySamples = Array.from({ length: 25 }, (_, index) => `C:\\ws\\sub\\f${index}.txt`)
    const enumJson = JSON.stringify([
      { path: 'C:\\ws\\gone', files: -1, dirs: -1, samples: [], truncated: false, missing: true },
      { path: 'C:\\ws\\sub', files: 1, dirs: 0, samples: manySamples, truncated: true },
    ])
    const { runner } = runnerWith(async (argv) => {
      const encoded = argv.includes('-EncodedCommand') ? argv[argv.indexOf('-EncodedCommand') + 1]! : ''
      const script = Buffer.from(encoded, 'base64').toString('utf16le')
      if (script.includes('$WhatIfPreference')) {
        return { stdout: 'What if: Performing the operation "Remove Directory" on target "C:\\ws\\sub".', stderr: '', exitCode: 0, timedOut: false }
      }
      return { stdout: enumJson, stderr: '', exitCode: 0, timedOut: false }
    })
    const outcome = await runner.preview('Remove-Item C:\\ws\\sub -Recurse')
    expect(outcome.kind).toBe('previewed')
    if (outcome.kind === 'previewed') {
      expect(outcome.fileCount).toBe(1)
      expect(outcome.directoryCount).toBe(1)
      expect(outcome.truncated).toBe(true)
      expect(outcome.samples.length).toBeLessThanOrEqual(10)
    }
  })

  it('marks a complete subtree as truncated when the global sample cap drops entries', async () => {
    const enumJson = JSON.stringify([
      { path: 'C:\\ws\\sub', files: 2, dirs: 0, samples: ['C:\\ws\\sub\\a.txt', 'C:\\ws\\sub\\b.txt'], truncated: false },
    ])
    const { runner } = runnerWith(async (argv) => {
      const encoded = argv.includes('-EncodedCommand') ? argv[argv.indexOf('-EncodedCommand') + 1]! : ''
      const script = Buffer.from(encoded, 'base64').toString('utf16le')
      if (script.includes('$WhatIfPreference')) {
        return { stdout: 'What if: Performing the operation "Remove Directory" on target "C:\\ws\\sub".', stderr: '', exitCode: 0, timedOut: false }
      }
      return { stdout: enumJson, stderr: '', exitCode: 0, timedOut: false }
    }, 2)
    const outcome = await runner.preview('Remove-Item C:\\ws\\sub -Recurse')
    expect(outcome).toMatchObject({ kind: 'previewed', objectCount: 3, samples: ['C:\\ws\\sub', 'C:\\ws\\sub\\a.txt'], truncated: true })
  })

  it('returns unpreviewable when the caller aborted before the dry run', async () => {
    const { runner, calls } = runnerWith(async () => ({ stdout: WHATIF_OUTPUT, stderr: '', exitCode: 0, timedOut: false }))
    const controller = new AbortController()
    controller.abort()
    expect((await runner.preview('Remove-Item x', controller.signal)).kind).toBe('unpreviewable')
    expect(calls).toHaveLength(0)
  })
})
