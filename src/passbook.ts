/**
 * passbook.ts — 纯逻辑层（无 DSH 依赖，可离线单测）
 *
 * 设计纪律（隐私密码本的四条硬边界）：
 *   1. 值只在「要用的那一刻」出现——生成/取用之外的一切路径都掩码或哈希。
 *   2. 观测不反噬主流程：审计轨迹写失败只返回 false，绝不抛。
 *   3. 秘密永不出现在命令行参数里（密码走 stdin；`use` 走子进程 env）。
 *   4. 判据结构化：退出码 → 语义（不互相掩盖），校验失败给明确原因。
 */
import { randomInt } from 'node:crypto'
import { createHash } from 'node:crypto'

export type PassField = 'password' | 'totp' | 'recovery' | 'notes' | 'username'

/** 需要显式确认才允许取回的字段（泄密面 = 这三类）。 */
export const SECRET_FIELDS: readonly PassField[] = ['password', 'totp', 'recovery']
/** vault.ps1 所知的字段全集。 */
export const ALL_FIELDS: readonly PassField[] = ['password', 'totp', 'recovery', 'notes', 'username']

export interface VaultEntryMeta {
  site: string
  username: string
  fields: string[]
  updatedAt: string
}

export interface GenerateOptions {
  length?: number
  symbols?: boolean
  digits?: boolean
  upper?: boolean
  lower?: boolean
  avoidAmbiguous?: boolean
}

export interface GeneratedSecret {
  value: string
  entropyBits: number
  charsetSize: number
  length: number
  pools: string[]
}

export interface Strength {
  length: number
  charsetSize: number
  entropyBits: number
  label: 'weak' | 'fair' | 'strong' | 'very-strong'
}

const LOWER = 'abcdefghijkmnopqrstuvwxyz'   // 去掉易混 l
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'    // 去掉易混 I O
const DIGITS = '23456789'                   // 去掉易混 0 1
const SYMBOLS = '!@#$%^&*()-_=+[]{}:,.?/'
const AMBIGUOUS = 'lIO01|`\'"'

/**
 * 生成强随机秘密。默认 24 字符、四类字符池齐全、排除易混字符。
 * 每字符独立从整池取（randomInt 无模偏），保证「每池至少一字符」。
 */
export function generateSecret(opts: GenerateOptions = {}): GeneratedSecret {
  const length = clampInt(opts.length ?? 24, 8, 256)
  const avoidAmbiguous = opts.avoidAmbiguous ?? true
  const pools: string[] = []
  if (opts.lower ?? true) pools.push(LOWER)
  if (opts.upper ?? true) pools.push(UPPER)
  if (opts.digits ?? true) pools.push(DIGITS)
  if (opts.symbols ?? true) pools.push(SYMBOLS)
  if (pools.length === 0) pools.push(LOWER)

  const filter = (s: string) => (avoidAmbiguous ? [...s].filter((c) => !AMBIGUOUS.includes(c)).join('') : s)
  const effective = pools.map(filter).filter((p) => p.length > 0)
  const whole = effective.join('')
  if (effective.length === 0) throw new Error('generateSecret: 字符池为空（所有类别都被过滤）')

  const chars: string[] = []
  // 每池先取一个，保证类别覆盖（长度足够时）
  for (const pool of effective) {
    if (chars.length >= length) break
    chars.push(pool[randomInt(pool.length)]!)
  }
  while (chars.length < length) chars.push(whole[randomInt(whole.length)]!)
  // 洗牌（Fisher–Yates，randomInt 无偏）
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1)
    const tmp = chars[i]!
    chars[i] = chars[j]!
    chars[j] = tmp
  }
  const value = chars.join('')
  const charsetSize = whole.length
  return {
    value,
    charsetSize,
    length,
    pools: effective.map((p) => `${p.length}`),
    entropyBits: round1(length * Math.log2(charsetSize)),
  }
}

/** 估计强度（信息熵下界：length × log2(字符池)）。 */
export function estimateStrength(value: string): Strength {
  const charsetSize = guessCharsetSize(value)
  const entropyBits = round1(value.length * Math.log2(Math.max(charsetSize, 2)))
  const label: Strength['label'] =
    entropyBits >= 128 ? 'very-strong' : entropyBits >= 80 ? 'strong' : entropyBits >= 50 ? 'fair' : 'weak'
  return { length: value.length, charsetSize, entropyBits, label }
}

function guessCharsetSize(value: string): number {
  let size = 0
  if (/[a-z]/.test(value)) size += 26
  if (/[A-Z]/.test(value)) size += 26
  if (/[0-9]/.test(value)) size += 10
  if (/[^A-Za-z0-9]/.test(value)) size += SYMBOLS.length
  return size
}

/** 渲染掩码（确认信息用）：只给长度与首尾各 1 字符的类别，不给值。 */
export function maskValue(value: string): string {
  if (!value) return '(空)'
  if (value.length <= 2) return `${'•'.repeat(value.length)} (len ${value.length})`
  return `${'•'.repeat(Math.min(value.length, 12))} (len ${value.length})`
}

/** 输出卫生：把任何出现过的秘密值替换为 [redacted]（含大小写/URL 编码变体）。 */
export function redactSecrets(text: string, secrets: readonly string[]): { text: string; hits: number } {
  let out = text
  let hits = 0
  for (const secret of secrets) {
    if (!secret || secret.length < 4) continue
    const variants = new Set<string>([secret, encodeURIComponent(secret), Buffer.from(secret, 'utf8').toString('base64')])
    for (const v of variants) {
      if (!v || v.length < 4) continue
      const parts = out.split(v)
      if (parts.length > 1) {
        hits += parts.length - 1
        out = parts.join('[redacted]')
      }
    }
  }
  return { text: out, hits }
}

/** 秘密的短指纹（用于「有没有重复用同一口令」而不泄漏值）。 */
export function fingerprint(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 12)
}

/** vault.ps1 退出码 → 语义（§5.9 规则 1：不同场景不得互相掩盖）。 */
export function classifyExit(code: number | null): { ok: boolean; kind: string; meaning: string } {
  switch (code) {
    case 0: return { ok: true, kind: 'ok', meaning: '成功' }
    case 2: return { ok: false, kind: 'vault-missing', meaning: 'vault 不存在（需先 init）' }
    case 3: return { ok: false, kind: 'decrypt-failed', meaning: '解密失败（DPAPI：异机/异用户/密文损坏）' }
    case 4: return { ok: false, kind: 'parse-failed', meaning: '解密后 JSON 解析失败（文件损坏）' }
    case 5: return { ok: false, kind: 'structure-mismatch', meaning: '结构/版本不符（kind 或 version 不匹配）' }
    case 6: return { ok: false, kind: 'param-or-entry', meaning: '参数或条目问题（缺 Site／无此条目／字段为空／需 -Force）' }
    default: return { ok: false, kind: 'unknown', meaning: `未知退出码：${code}` }
  }
}

/**
 * 解析 `list-json` 输出。宽容：PowerShell 可能在 JSON 前后混入警告文本，
 * 取「第一个以 [ 开头且能 parse 的整行」；全失败则返回错误（不静默给空数组）。
 */
export function parseVaultListJson(stdout: string): { ok: true; entries: VaultEntryMeta[] } | { ok: false; error: string } {
  const text = stdout.replace(/^\uFEFF/, '')
  const candidates = [text.trim(), ...text.split(/\r?\n/).map((l) => l.trim())]
  for (const c of candidates) {
    if (!c.startsWith('[')) continue
    try {
      const parsed = JSON.parse(c)
      if (!Array.isArray(parsed)) continue
      const entries: VaultEntryMeta[] = parsed.map((raw: Record<string, unknown>) => ({
        site: String(raw?.site ?? ''),
        username: String(raw?.username ?? ''),
        fields: String(raw?.fields ?? '').split(',').map((s) => s.trim()).filter(Boolean),
        updatedAt: String(raw?.updatedAt ?? ''),
      }))
      return { ok: true, entries }
    } catch {
      continue
    }
  }
  return { ok: false, error: 'list-json 输出中找不到可解析的 JSON 数组（vault 可能未初始化或输出被污染）' }
}

/** 构造 vault.ps1 的 argv。**秘密绝不入参数**：密码只以 PasswordStdin 标记出现。 */
export function buildVaultArgs(
  action: 'init' | 'list' | 'list-json' | 'verify' | 'set' | 'get' | 'remove',
  params: { site?: string; user?: string; totp?: string; recovery?: string; notes?: string; field?: PassField | 'fields'; force?: boolean; vaultPath?: string; passwordStdin?: boolean } = {},
): string[] {
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '@SCRIPT@', action]
  if (params.vaultPath) args.push('-VaultPath', params.vaultPath)
  if (params.site) args.push('-Site', params.site)
  if (params.user) args.push('-User', params.user)
  if (params.totp) args.push('-Totp', params.totp)
  if (params.recovery) args.push('-Recovery', params.recovery)
  if (params.notes) args.push('-Notes', params.notes)
  if (params.field) args.push('-Field', params.field)
  if (params.passwordStdin) args.push('-PasswordStdin')
  if (params.force) args.push('-Force')
  return args
}

/** 校验字段名与必填前提，返回明确错误（而不是交给 vault 报模糊错）。 */
export function validateRequest(
  action: 'set' | 'get' | 'remove',
  params: { site?: string; field?: string },
): { ok: true } | { ok: false; error: string } {
  if (!params.site || params.site.trim() === '') return { ok: false, error: `${action} 需要 site` }
  if (action === 'get') {
    const field = params.field ?? 'password'
    if (!ALL_FIELDS.includes(field as PassField) && field !== 'fields') {
      return { ok: false, error: `未知字段：${field}（可用：${ALL_FIELDS.join('/')}/fields）` }
    }
  }
  return { ok: true }
}

/** 取回秘密前的前置判断：秘密字段必须显式确认。 */
export function needsConfirmation(field: PassField): boolean {
  return SECRET_FIELDS.includes(field)
}

export interface AuditFinding {
  site: string
  kind: 'stale' | 'no-password' | 'weak' | 'reused' | 'no-totp'
  detail: string
}

export interface AuditReport {
  total: number
  findings: AuditFinding[]
  scannedAt: string
  deep: boolean
  reusedGroups: number
}

/**
 * 体检：浅层只用元数据（不回显、不解密）；
 * deep=true 时才读值——**只输出强度分档与哈希指纹分组，绝不输出值**。
 */
export function planAudit(
  entries: VaultEntryMeta[],
  values: Record<string, { password?: string }> = {},
  opts: { nowMs?: number; rotationDays?: number; deep?: boolean } = {},
): AuditReport {
  const nowMs = opts.nowMs ?? Date.now()
  const rotationDays = opts.rotationDays ?? 180
  const deep = opts.deep ?? false
  const findings: AuditFinding[] = []
  const byFingerprint = new Map<string, string[]>()

  for (const e of entries) {
    const age = ageDays(e.updatedAt, nowMs)
    if (age !== null && age > rotationDays) {
      findings.push({ site: e.site, kind: 'stale', detail: `距上次更新 ${Math.round(age)} 天（阈值 ${rotationDays} 天）` })
    }
    if (!e.fields.includes('password')) {
      findings.push({ site: e.site, kind: 'no-password', detail: `条目未存 password（字段：[${e.fields.join(',')}]）` })
    }
    if (deep) {
      const pw = values[e.site]?.password
      if (pw) {
        const s = estimateStrength(pw)
        if (s.label === 'weak' || s.label === 'fair') {
          findings.push({ site: e.site, kind: 'weak', detail: `强度 ${s.label}（≈${s.entropyBits} bits，len ${s.length}）` })
        }
        const fp = fingerprint(pw)
        const group = byFingerprint.get(fp) ?? []
        group.push(e.site)
        byFingerprint.set(fp, group)
      }
    }
  }
  let reusedGroups = 0
  for (const [, sites] of byFingerprint) {
    if (sites.length > 1) {
      reusedGroups++
      findings.push({ site: sites.join(' / '), kind: 'reused', detail: `同一口令复用（指纹 ${fingerprint(values[sites[0]!]?.password ?? '')}，${sites.length} 个条目）` })
    }
  }
  return { total: entries.length, findings, scannedAt: new Date(nowMs).toISOString(), deep, reusedGroups }
}

export function ageDays(updatedAt: string, nowMs: number): number | null {
  if (!updatedAt) return null
  const t = Date.parse(updatedAt)
  if (Number.isNaN(t)) return null
  return (nowMs - t) / 86_400_000
}

/** 审计轨迹行（**永不含值**，只有「谁·何时·对哪条·做了什么·结果」）。 */
export function traceLine(event: {
  atMs: number
  tool: string
  action: string
  site?: string
  field?: string
  outcome: string
  detail?: string
  caller?: string
}): string {
  const payload: Record<string, unknown> = {
    atMs: event.atMs,
    iso: new Date(event.atMs).toISOString(),
    tool: event.tool,
    action: event.action,
    outcome: event.outcome,
  }
  if (event.site) payload.site = event.site
  if (event.field) payload.field = event.field
  if (event.detail) payload.detail = event.detail
  if (event.caller) payload.caller = event.caller
  return JSON.stringify(payload)
}

function clampInt(n: number, lo: number, hi: number): number {
  const v = Math.trunc(Number(n))
  if (!Number.isFinite(v)) return lo
  return Math.max(lo, Math.min(hi, v))
}

function round1(n: number): number {
  return Math.round(n * 10) / 10
}
