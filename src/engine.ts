/**
 * The guard engine: one judge pass per shell tool call. The guard is active
 * ONLY in `careful-full-access` — every other sandbox mode passes through
 * untouched (workspace-write is already confined by the sandbox itself, and
 * danger-full-access is the user's explicit opt-out). Inside careful mode the
 * engine runs the cheap lexical scan first (the fast allow gate for the
 * overwhelming majority of commands), spawns the AST analyzer only for
 * destructive signals, maps the tier verdict onto the review route, and
 * resolves every flagged command through the WhatIf preview (deletions) and
 * the model-check three-question review — with human confirmation as the last
 * layer for disaster-tier or model-declared-dangerous commands.
 *
 * @module dsh-careful-full-access/engine
 */

import type { PwshAnalyzer } from './analyzer.ts'
import { hasDestructiveSignal, lexBash, lexPwsh, type LexFacts } from './lexer.ts'
import type { ModelCheckOutcome, ModelCheckRoute, ModelCheckRunner } from './model-check.ts'
import { PreviewRunner, renderPreviewSummary } from './preview.ts'
import type { ProtectedRoots } from './protected.ts'
import { classifyBash, classifyPwsh, type TierContext } from './tiers.ts'
import type { GuardTier, GuardVerdict, PreviewOutcome } from './types.ts'

/** The engine's settled decision for one call. */
export type EngineDecision =
  | { kind: 'allow'; tier?: GuardTier; modelCheck?: ModelCheckOutcome['kind'] }
  | { kind: 'deny'; tier?: GuardTier; reason: string; modelCheck?: ModelCheckOutcome['kind'] }
  | { kind: 'ask'; tier?: GuardTier; reason: string; severity?: 'danger'; modelCheck?: ModelCheckOutcome['kind'] }

/** Engine construction facts resolved once per plugin apply. */
export interface EngineOptions {
  analyzer: PwshAnalyzer
  preview: PreviewRunner
  protectedRoots: ProtectedRoots
  modelCheck: ModelCheckRunner
}

/** One judgment request: the shell call facts the engine needs. */
export interface JudgeInput {
  dialect: 'pwsh' | 'bash'
  command: string
  /**
   * The per-call resolved sandbox mode as text; undefined when no policy is
   * mounted. Kept as a plain string so the plugin also compiles against
   * published DSH types whose `SandboxMode` does not yet include
   * `careful-full-access`; the engine only ever compares it to that literal.
   */
  mode: string | undefined
  /** The per-call workspace root; undefined when no policy is mounted. */
  workspaceRoot: string | undefined
  /** The tool-call abort signal, observed around every spawn. */
  signal?: AbortSignal
  /** Scopes the session audit gate to one session. */
  sessionKey: string
  /** The session's model route for the model-check call. */
  route: ModelCheckRoute | undefined
}

/** Quote one command or path without losing whitespace or escape characters. */
function quoteForApproval(value: string): string {
  return JSON.stringify(value)
}

/** Describe the destructive effect without claiming that an unexpanded expression is a concrete target. */
function describeOperation(facts: LexFacts): string {
  if (facts.git?.subcommand === 'clean') return '删除 Git 工作区中未跟踪的文件和目录'
  if (facts.git?.subcommand === 'reset') return '用仓库版本覆盖 Git 工作区文件，未提交的修改会丢失'
  if (facts.git?.subcommand === 'rm') return '从 Git 索引和工作区删除已跟踪的文件'
  if (facts.families.includes('format') || facts.diskpartClean) return '格式化或清空存储设备，其中的数据可能全部丢失'
  if (facts.families.includes('recycle')) return '清空回收站，其中的内容会被永久删除'
  if (facts.robocopyMir) return '执行镜像同步，并删除目标端中源目录不存在的内容'
  if (facts.families.includes('delete') || facts.netDeleteCall) {
    return facts.recursive ? '递归删除指定目标及其子项' : '删除指定的文件或目录'
  }
  return '执行可能删除或覆盖数据的高风险操作'
}

/** Render the concrete or explicitly unknown deletion scope for a human approver. */
function describeScope(
  preview: PreviewOutcome | undefined,
  facts: LexFacts,
  dialect: JudgeInput['dialect'],
): string {
  if (preview?.kind === 'previewed') {
    const counts = `WhatIf 预演解析出 ${preview.objectCount} 个对象（${preview.fileCount} 个文件、${preview.directoryCount} 个目录）`
    if (preview.samples.length === 0) return `${counts}；预演没有返回可显示的目标名称`
    const targets = preview.samples.map(quoteForApproval).join('、')
    return preview.truncated
      ? `${counts}；目标清单仅显示前 ${preview.samples.length} 个：${targets}；其余对象未显示`
      : `${counts}；完整目标清单：${targets}`
  }
  if (preview?.kind === 'protected-hit') {
    return `WhatIf 预演解析到受保护根目录 ${quoteForApproval(preview.target)}；该根目录范围内的数据都可能被删除，未展开逐文件清单`
  }
  if (preview?.kind === 'unpreviewable') {
    return 'WhatIf 预演未能可靠完成，无法准确列出实际文件；缺少清单不表示命令不会删除文件'
  }
  if (facts.families.includes('delete') || facts.netDeleteCall) {
    const expressions = facts.literalPaths.length === 0
      ? '命令中没有可静态确认的目标路径'
      : `命令中的目标表达式：${facts.literalPaths.map(quoteForApproval).join('、')}`
    return dialect === 'bash'
      ? `Bash 删除命令没有 WhatIf 预演，无法可靠展开通配符、变量或递归目录；${expressions}`
      : `没有取得可验证的逐文件清单；${expressions}`
  }
  return '这类操作无法按普通文件删除逐项预览；命令所指向范围内的数据都可能受到影响'
}

/** Localize the model-check outcome without exposing its free-form working language. */
function describeModelCheck(outcome: 'safe' | 'dangerous' | 'unavailable'): string {
  switch (outcome) {
    case 'safe': return '模型复核认为命令符合原意，但此风险级别仍要求你亲自批准'
    case 'dangerous': return '模型复核认为此操作有危险，必须由你决定是否继续'
    case 'unavailable': return '模型复核不可用，无法确认安全性，因此按最高风险请求批准'
  }
}

/** Localize the classifier tier for the approval surface. */
function describeTier(tier: Exclude<GuardTier, 'normal'>): string {
  switch (tier) {
    case 'disaster': return '灾难级'
    case 'unparseable': return '无法可靠解析（按灾难级处理）'
    case 'elevated': return '高风险'
  }
}

/**
 * The stateless-per-call orchestrator. All instance state lives in the
 * injected runners (model-check, preview, analyzer), so one engine instance
 * serves every session.
 */
export class GuardEngine {
  constructor(private readonly options: EngineOptions) {}

  /**
   * Judge one shell call.
   * @param input - the call facts.
   * @returns the careful-mode decision; every other mode allows outright.
   */
  async judge(input: JudgeInput): Promise<EngineDecision> {
    if (input.mode !== 'careful-full-access') return { kind: 'allow' }
    const context: TierContext = {
      ...input.workspaceRoot === undefined ? {} : { workspaceRoot: input.workspaceRoot },
      protectedRoots: this.options.protectedRoots,
    }
    if (input.dialect === 'bash') return this.judgeBash(input, context)
    return this.judgePwsh(input, context)
  }

  private async judgePwsh(input: JudgeInput, context: TierContext): Promise<EngineDecision> {
    const facts = lexPwsh(input.command)
    if (!hasDestructiveSignal(facts)) return { kind: 'allow' }
    // The lex-only pass already proves disaster and git subcommand semantics;
    // everything else is refined through the AST analyzer.
    const fast = classifyPwsh(input.command, undefined, facts, context)
    const verdict = fast.tier === 'disaster' || facts.git !== undefined
      ? fast
      : classifyPwsh(input.command, await this.options.analyzer.analyze(input.command, input.signal), facts, context)
    return this.route(input, verdict, 'pwsh', facts)
  }

  private async judgeBash(input: JudgeInput, context: TierContext): Promise<EngineDecision> {
    const facts = lexBash(input.command)
    if (!hasDestructiveSignal(facts)) return { kind: 'allow' }
    const verdict = classifyBash(facts, context)
    return this.route(input, verdict, 'bash', facts)
  }

  /** Every flagged command runs the review route; only `normal` allows straight through. */
  private async route(
    input: JudgeInput,
    verdict: GuardVerdict,
    dialect: 'pwsh' | 'bash',
    facts: LexFacts,
  ): Promise<EngineDecision> {
    if (verdict.tier === 'normal') return { kind: 'allow' }
    return this.review(input, verdict, dialect, facts)
  }

  /** The review route: optional WhatIf scope, then the model-check three questions. */
  private async review(
    input: JudgeInput,
    verdict: GuardVerdict,
    dialect: 'pwsh' | 'bash',
    facts: LexFacts,
  ): Promise<EngineDecision> {
    // route() only reaches the review for non-normal verdicts; the cast is the
    // one place the classifier's closed union narrows to the review tiers.
    const reviewTier = verdict.tier as Exclude<GuardTier, 'normal'>
    let effectiveTier: Exclude<GuardTier, 'normal'> = reviewTier
    let scopeSummary: string | undefined
    let deletionPreview: PreviewOutcome | undefined
    if (dialect === 'pwsh' && facts.families.includes('delete')) {
      const outcome = await this.options.preview.preview(input.command, input.signal)
      switch (outcome.kind) {
        case 'zero-targets':
          // The dry run proved the command deletes nothing — nothing to review.
          return { kind: 'allow', tier: effectiveTier }
        case 'previewed':
          deletionPreview = outcome
          scopeSummary = renderPreviewSummary(outcome.fileCount, outcome.directoryCount, outcome.samples, outcome.truncated)
          break
        case 'protected-hit':
          // The resolved scope IS a protected root: upgrade to the disaster tier
          // so the human confirmation carries the red disaster marking.
          effectiveTier = 'disaster'
          deletionPreview = outcome
          scopeSummary = `resolved to the protected root "${outcome.target}"`
          break
        case 'unpreviewable':
          deletionPreview = outcome
          break
        /* v8 ignore next 3 -- PreviewOutcome is a typed same-process closed union; this branch is only the static exhaustiveness guard. */
        default: {
          const never: never = outcome
          throw new Error(`unreachable preview outcome: ${String(never)}`)
        }
      }
    }
    const outcome = await this.options.modelCheck.check({
      command: input.command,
      tier: reviewTier,
      reason: verdict.reason,
      ...scopeSummary === undefined ? {} : { scopeSummary },
      route: input.route,
      ...input.signal === undefined ? {} : { signal: input.signal },
    })
    switch (outcome.kind) {
      case 'not-intended':
        // The model disowns the command — this is the misparse case the guard
        // exists for. No human confirmation: the model said no itself.
        return {
          kind: 'deny',
          tier: verdict.tier,
          modelCheck: 'not-intended',
          reason: `command guard: model-check concluded this command was not the intended one: ${outcome.explanation}`,
        }
      case 'safe':
        if (effectiveTier === 'elevated') return { kind: 'allow', tier: 'elevated', modelCheck: 'safe' }
        return {
          kind: 'ask',
          tier: effectiveTier,
          severity: 'danger',
          modelCheck: 'safe',
          reason: this.confirmReason(input, effectiveTier, facts, deletionPreview, 'safe'),
        }
      case 'dangerous':
        return {
          kind: 'ask',
          tier: effectiveTier,
          ...effectiveTier === 'disaster' || effectiveTier === 'unparseable' ? { severity: 'danger' as const } : {},
          modelCheck: 'dangerous',
          reason: this.confirmReason(input, effectiveTier, facts, deletionPreview, 'dangerous'),
        }
      case 'unavailable':
        // Fail closed: a review that could not run is treated as disaster.
        return {
          kind: 'ask',
          tier: effectiveTier,
          severity: 'danger',
          modelCheck: 'unavailable',
          reason: this.confirmReason(
            input,
            effectiveTier === 'elevated' ? 'unparseable' : effectiveTier,
            facts,
            deletionPreview,
            'unavailable',
          ),
        }
      /* v8 ignore next 3 -- ModelCheckOutcome is a typed same-process closed union; this branch is only the static exhaustiveness guard. */
      default: {
        const never: never = outcome
        throw new Error(`unreachable model-check outcome: ${String(never)}`)
      }
    }
  }

  /** Assemble the Chinese human-confirmation text from the exact command and the verified deletion scope. */
  private confirmReason(
    input: JudgeInput,
    tier: Exclude<GuardTier, 'normal'>,
    facts: LexFacts,
    preview: PreviewOutcome | undefined,
    modelCheck: 'safe' | 'dangerous' | 'unavailable',
  ): string {
    return `删除或破坏性命令需要人工批准。准备执行：${quoteForApproval(input.command)}。操作说明：${describeOperation(facts)}。删除范围：${describeScope(preview, facts, input.dialect)}。风险级别：${describeTier(tier)}。${describeModelCheck(modelCheck)}。请只在命令和删除范围都符合预期时批准一次。`
  }
}
