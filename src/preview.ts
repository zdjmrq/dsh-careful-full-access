/**
 * The careful-full-access preview pipeline: a read-only dry run that resolves
 * the command's REAL deletion scope before anything executes. The dry run sets
 * `$WhatIfPreference = $true` — the engine-level switch every ShouldProcess
 * cmdlet honors — so wildcards, variables, and `$env:` expansions are resolved
 * by PowerShell itself, not by the guard's parsing. `What if:` lines give the
 * concrete target list; recursive directory targets get one extra read-only
 * subtree enumeration (the dry run alone prints only the top directory), and
 * any resolved target that IS a protected root reports `protected-hit` (the
 * engine upgrades it to the disaster tier for the review).
 *
 * The command runs once with WhatIf on, so non-delete side effects before a
 * delete cmdlet DO execute during the preview — a documented tradeoff of
 * asking the shell itself for the truth.
 *
 * @module dsh-careful-full-access/preview
 */

import type { PreviewOutcome, Spawner } from './types.ts'
import { encodeCommand } from './analyzer.ts'
import { isProtectedTarget, type ProtectedRoots } from './protected.ts'

/** One dry-run line: `What if: Performing the operation "Remove File" on target "D:\x".` */
const WHATIF_LINE = /^what if:.*?operation\s+"([^"]+)"\s+on\s+target\s+"([^"]+)"/i
/** The localized (zh-CN) form: `假设: 正在目标“D:\x”上执行操作“Remove File”。` */
const WHATIF_LINE_ZH = /^假设[:：]\s*正在目标[“"]([^”"]+)[”"]上执行操作[“"]([^”"]+)[”"]/

/** The dry-run wrapper: preference on, then the command as written. */
const PREVIEW_SCRIPT = String.raw`
$WhatIfPreference = $true
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
`
/** The subtree enumeration script: counts and samples per resolved directory. */
const ENUMERATE_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$out = @()
foreach ($t in $targets) {
  if (Test-Path -LiteralPath $t -PathType Container) {
    $items = @(Get-ChildItem -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue)
    $fileCount = 0
    $dirCount = 0
    foreach ($item in $items) { if ($item.PSIsContainer) { $dirCount += 1 } else { $fileCount += 1 } }
    $samples = @($items | Select-Object -First 10 | ForEach-Object { $_.FullName })
    $out += [ordered]@{ path = $t; files = $fileCount; dirs = $dirCount; samples = $samples; truncated = ($items.Count -gt 10) }
  } else {
    $out += [ordered]@{ path = $t; files = -1; dirs = -1; samples = @(); truncated = $false; missing = $true }
  }
}
$out | ConvertTo-Json -Depth 5 -Compress
`

/** One parsed dry-run target. */
interface DryRunTarget {
  op: string
  target: string
}

/** One enumerated directory subtree. */
interface EnumeratedSubtree {
  path: string
  files: number
  dirs: number
  samples: string[]
  truncated: boolean
  missing?: boolean
}

/** The preview configuration. */
export interface PreviewOptions {
  /** Kill deadline for each helper spawn. */
  timeoutMs: number
  /** Sample-path cap in the final summary. */
  sampleLimit: number
  /** The helper executable, already resolved from config defaults. */
  pwshPath: string
}

/** Parse every `What if:` line (English or zh-CN form) from the dry-run output. */
export function parseWhatIfLines(stdout: string): DryRunTarget[] {
  const targets: DryRunTarget[] = []
  for (const line of stdout.split(/\r?\n/)) {
    const match = WHATIF_LINE.exec(line)
    if (match !== null) {
      const op = match[1]
      const target = match[2]
      /* v8 ignore next -- both capture groups always exist for a matching line; the check only guards hostile regex drift */
      if (op === undefined || target === undefined) continue
      targets.push({ op, target })
      continue
    }
    const zhMatch = WHATIF_LINE_ZH.exec(line)
    if (zhMatch !== null) {
      const op = zhMatch[2]
      const target = zhMatch[1]
      /* v8 ignore next -- both capture groups always exist for a matching line; the check only guards hostile regex drift */
      if (op === undefined || target === undefined) continue
      targets.push({ op, target })
    }
  }
  return targets
}

/** Parse and validate the enumeration script's JSON output. */
export function parseEnumeration(stdout: string): EnumeratedSubtree[] | undefined {
  const line = stdout.trim().split(/\r?\n/).filter(part => part.length > 0).at(-1)
  if (line === undefined) return undefined
  try {
    const parsed: unknown = JSON.parse(line)
    if (!Array.isArray(parsed)) return undefined
    return parsed.map((entry): EnumeratedSubtree | undefined => {
      if (typeof entry !== 'object' || entry === null) return undefined
      const record = entry as Record<string, unknown>
      if (typeof record['path'] !== 'string'
        || typeof record['files'] !== 'number'
        || typeof record['dirs'] !== 'number'
        || !Array.isArray(record['samples'])) return undefined
      return {
        path: record['path'],
        files: record['files'],
        dirs: record['dirs'],
        samples: (record['samples'] as unknown[]).filter((item): item is string => typeof item === 'string'),
        truncated: record['truncated'] === true,
        ...record['missing'] === true ? { missing: true } : {},
      }
    }).filter((item): item is EnumeratedSubtree => item !== undefined)
  } catch {
    return undefined
  }
}

/** Build the enumeration script with the resolved targets embedded as a literal array. */
function buildEnumerationScript(targets: readonly string[]): string {
  const literal = targets.map(target => JSON.stringify(target)).join(', ')
  return `$targets = @(${literal})\n${ENUMERATE_SCRIPT}`
}

/** Render the bounded model-facing preview summary. */
export function renderPreviewSummary(fileCount: number, directoryCount: number, samples: readonly string[], truncated: boolean): string {
  const total = fileCount + directoryCount
  const head = `command guard preview: this deletion resolves to ${total} objects (${fileCount} files, ${directoryCount} directories)`
  const sampleText = samples.length > 0
    ? `; first targets: ${samples.map(sample => `"${sample}"`).join(', ')}${truncated ? ', …' : ''}`
    : ''
  return head + sampleText + ' — verify this scope matches your intent'
}

/**
 * Run the two-stage preview: WhatIf dry run, then subtree enumeration for the
 * resolved directory targets. Protected-root hits refuse before enumeration.
 */
export class PreviewRunner {
  constructor(
    private readonly spawner: Spawner,
    private readonly options: PreviewOptions,
    private readonly protectedRoots: ProtectedRoots,
  ) {}

  /**
   * Dry-run one command and resolve its real deletion scope.
   * @param command - the model-supplied command text.
   * @param signal - the tool-call abort signal.
   * @returns the preview outcome; every failure shape is fail-closed.
   */
  async preview(command: string, signal?: AbortSignal): Promise<PreviewOutcome> {
    if (signal?.aborted) return { kind: 'unpreviewable', detail: 'the call was aborted before the preview ran' }
    const dryRun = await this.spawner(
      [this.options.pwshPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodeCommand(PREVIEW_SCRIPT + command)],
      { timeoutMs: this.options.timeoutMs },
    )
    if (dryRun.spawnError !== undefined || dryRun.exitCode === null || dryRun.timedOut) {
      return { kind: 'unpreviewable', detail: 'the dry run could not complete (spawn failure or timeout)' }
    }
    const targets = parseWhatIfLines(dryRun.stdout)
    if (targets.length === 0) {
      return dryRun.exitCode === 0
        ? { kind: 'zero-targets' }
        : { kind: 'unpreviewable', detail: 'the dry run produced no preview targets and exited non-zero' }
    }
    for (const { target } of targets) {
      if (isProtectedTarget(target, this.protectedRoots)) return { kind: 'protected-hit', target }
    }
    const fileTargets = targets.filter(entry => !entry.op.toLowerCase().includes('directory')).length
    const directoryTargets = targets.filter(entry => entry.op.toLowerCase().includes('directory')).map(entry => entry.target)
    if (directoryTargets.length === 0) {
      return {
        kind: 'previewed',
        objectCount: fileTargets,
        fileCount: fileTargets,
        directoryCount: 0,
        samples: targets.slice(0, this.options.sampleLimit).map(entry => entry.target),
        truncated: targets.length > this.options.sampleLimit,
      }
    }
    const enumeration = await this.spawner(
      [this.options.pwshPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodeCommand(buildEnumerationScript(directoryTargets))],
      { timeoutMs: this.options.timeoutMs },
    )
    if (enumeration.spawnError !== undefined || enumeration.exitCode !== 0 || enumeration.timedOut) {
      return { kind: 'unpreviewable', detail: 'the subtree enumeration could not complete (spawn failure or timeout)' }
    }
    const subtrees = parseEnumeration(enumeration.stdout)
    if (subtrees === undefined) return { kind: 'unpreviewable', detail: 'the subtree enumeration produced unreadable output' }
    const missingDirectories = new Set(subtrees.filter(subtree => subtree.missing === true).map(subtree => subtree.path))
    const resolvedTargets = targets.filter(entry => !missingDirectories.has(entry.target))
    let fileCount = fileTargets
    let directoryCount = 0
    const samples: string[] = resolvedTargets.slice(0, this.options.sampleLimit).map(entry => entry.target)
    let truncated = resolvedTargets.length > this.options.sampleLimit
    for (const subtree of subtrees) {
      if (subtree.missing === true) continue
      fileCount += subtree.files
      // The subtree enumeration counts descendants only; the top-level target
      // directory is also deleted and belongs in the approval total.
      directoryCount += subtree.dirs + 1
      for (const sample of subtree.samples) {
        if (samples.length < this.options.sampleLimit) samples.push(sample)
        else truncated = true
      }
      truncated = truncated || subtree.truncated
    }
    const objectCount = fileCount + directoryCount
    truncated = truncated || objectCount > samples.length
    return { kind: 'previewed', objectCount, fileCount, directoryCount, samples, truncated }
  }
}

/** A summary line for tests and the engine's deny reason. */
export function previewDenyReason(outcome: Extract<PreviewOutcome, { kind: 'previewed' }>): string {
  return renderPreviewSummary(outcome.fileCount, outcome.directoryCount, outcome.samples, outcome.truncated)
}
