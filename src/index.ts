/**
 * dsh-passbook（隐私密码本）
 *
 * 唯一职责：把「我自己的私密凭据」变成可调用、可审计、可体检的工具面——
 *   生成强秘密 / 字段级写入 / 按需取用（需显式确认）/ **不泄漏地使用**（env 注入）/ 体检 / 端到端自检。
 *
 * 四条硬边界（写进 README 与语义文档，不做虚假安全承诺）：
 *   1. **存储不重写**：复用 alice-identity 的 DPAPI vault（vault.ps1）——单一真源，同一套加密路径。
 *      诚实边界：DPAPI 以 CurrentUser + 本机为界，防「异机 / 异用户 / 误入仓库」，
 *      **防不了本机的账号主人**（同机是物理事实）。
 *   2. **值最小暴露**：秘密只在「真的要用的那一刻」出现；`passbook_use` 走子进程 env 注入，
 *      子进程输出里的秘密一律替换为 [redacted]。
 *   3. **审计不记值**：`<DSH_HOME>/passbook-trace.jsonl` 只记「谁·何时·对哪条·做了什么·结果」。
 *   4. **观测不反噬**：轨迹写失败只返回 false，绝不抛（§5.22 规则 3）。
 */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { spawn } from 'node:child_process'
import { appendFileSync, mkdirSync, rmSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { randomUUID } from 'node:crypto'
import {
  ALL_FIELDS,
  buildVaultArgs,
  classifyExit,
  estimateStrength,
  fingerprint,
  generateSecret,
  maskValue,
  needsConfirmation,
  parseVaultListJson,
  planAudit,
  redactSecrets,
  traceLine,
  validateRequest,
  type PassField,
  type VaultEntryMeta,
} from './passbook.ts'

export const name = 'passbook'
export const inject = ['tools'] as const

export interface Config {
  enabled: boolean
  /** vault.ps1 路径（本机专用 ⇒ 走配置默认值，不在逻辑里散落常量）。 */
  vaultScript: string
  /** 覆盖 vault 文件路径（空 = 用脚本默认库）。夹具隔离/自检用。 */
  vaultPath: string
  powershell: string
  /** 审计轨迹文件（空 = <DSH_HOME>/passbook-trace.jsonl）。 */
  traceFile: string
  rotationDays: number
  timeoutMs: number
}

export const Config = z.object({
  enabled: z.boolean().default(true),
  vaultScript: z.string().default('E:\\alice\\projects\\self\\alice-identity\\scripts\\vault.ps1'),
  vaultPath: z.string().default(''),
  powershell: z.string().default('powershell.exe'),
  traceFile: z.string().default(''),
  rotationDays: z.number().default(180),
  timeoutMs: z.number().default(60_000),
})

interface RunResult {
  code: number | null
  stdout: string
  stderr: string
  timedOut: boolean
}

export function apply(ctx: Context, config: Config): void {
  const logger = ctx.logger('passbook')
  const traceFile = config.traceFile || join(process.env['DSH_HOME'] ?? process.cwd(), 'passbook-trace.jsonl')

  function appendTrace(event: Parameters<typeof traceLine>[0]): boolean {
    try {
      mkdirSync(dirname(traceFile), { recursive: true })
      appendFileSync(traceFile, traceLine(event) + '\n', 'utf8')
      return true
    } catch (err) {
      logger.warn(`轨迹写入失败（不影响主流程）：${String(err)}`)
      return false
    }
  }

  function runVault(
    action: Parameters<typeof buildVaultArgs>[0],
    params: Parameters<typeof buildVaultArgs>[1] = {},
    stdin?: string,
  ): Promise<RunResult> {
    const argv = buildVaultArgs(action, {
      ...params,
      vaultPath: params.vaultPath ?? (config.vaultPath || undefined),
    })
    const script = config.vaultScript
    const args = argv.map((a) => (a === '@SCRIPT@' ? script : a))
    return new Promise<RunResult>((resolve) => {
      const child = spawn(config.powershell, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
      let stdout = ''
      let stderr = ''
      let settled = false
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        try { child.kill() } catch { /* 已退出 */ }
        resolve({ code: null, stdout, stderr, timedOut: true })
      }, config.timeoutMs)
      child.stdout.on('data', (d: Buffer) => { stdout += d.toString('utf8') })
      child.stderr.on('data', (d: Buffer) => { stderr += d.toString('utf8') })
      child.on('error', (err: Error) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve({ code: null, stdout, stderr: stderr + String(err.message), timedOut: false })
      })
      child.on('close', (code: number | null) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve({ code, stdout, stderr, timedOut: false })
      })
      if (stdin !== undefined) child.stdin.write(stdin, 'utf8')
      child.stdin.end()
    })
  }

  const stdoutText = (r: RunResult): string => r.stdout.trim()

  function failure(r: RunResult, extra?: string): { ok: false; kind: string; text: string } {
    const info = classifyExit(r.code)
    const detail = [stdoutText(r), r.stderr.trim(), extra].filter(Boolean).join(' | ')
    return {
      ok: false,
      kind: r.timedOut ? 'timeout' : info.kind,
      text: `${info.meaning}${detail ? `：${detail}` : ''}`,
    }
  }

  // render 签名是 (args, value)：第一参是参数、**第二参才是返回值**。
  // 写成单参会把参数渲染出来（实测踩过一次：工具调用显示 {} 而轨迹显示 ok）。
  const textOut = (_args: unknown, value: unknown): Array<{ type: 'text'; text: string }> => [{ type: 'text', text: JSON.stringify(value) }]

  // ── 1. 列出条目（非密元数据） ────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_list',
    description:
      '列出隐私密码本的条目**非密元数据**（site / username / 已存字段 / 更新时间）。'
      + '用于回答「我注册或存过哪些站点、每条有哪些字段」——不返回任何口令、TOTP 种子或恢复码。'
      + '要取值走 passbook_get（需显式确认）；要体检走 passbook_audit。',
    parameters: {},
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          count: { type: 'number' },
          entries: { type: 'array', items: { type: 'string' } },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(_args: Record<string, unknown>, exec: unknown) {
      const caller = callerOf(exec)
      const r = await runVault('list-json')
      if (r.code !== 0) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_list', action: 'list', outcome: 'failed', detail: classifyExit(r.code).kind, caller })
        return { ok: false, count: 0, entries: [], text: failure(r).text } as never
      }
      const parsed = parseVaultListJson(r.stdout)
      if (!parsed.ok) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_list', action: 'list', outcome: 'parse-failed', detail: parsed.error, caller })
        return { ok: false, count: 0, entries: [], text: parsed.error } as never
      }
      const entries = parsed.entries.map((e) => `${e.site} | user=${e.username || '(空)'} | 字段=[${e.fields.join(',')}] | 更新=${e.updatedAt}`)
      appendTrace({ atMs: Date.now(), tool: 'passbook_list', action: 'list', outcome: 'ok', detail: `${parsed.entries.length} 条`, caller })
      return { ok: true, count: parsed.entries.length, entries, text: `共 ${parsed.entries.length} 条` } as never
    },
  }))

  // ── 2. 查单条字段清单（非密） ────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_fields',
    description: '查某条密码本已存了哪些字段（只看**字段名**，不看值）。写值前先查一次，避免覆盖或漏填。',
    parameters: { site: { type: 'string', required: true, description: '条目 site 名（如 github）' } },
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          site: { type: 'string' },
          fields: { type: 'array', items: { type: 'string' } },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(args: { site: string }, exec: unknown) {
      const caller = callerOf(exec)
      const r = await runVault('get', { site: args.site, field: 'fields' })
      if (r.code !== 0) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_fields', action: 'fields', site: args.site, outcome: 'failed', detail: classifyExit(r.code).kind, caller })
        return { ok: false, site: args.site, fields: [], text: failure(r).text } as never
      }
      const m = /字段=\[([^\]]*)\]/.exec(stdoutText(r))
      const fields = m?.[1] ? m[1].split(',').map((s) => s.trim()).filter(Boolean) : []
      appendTrace({ atMs: Date.now(), tool: 'passbook_fields', action: 'fields', site: args.site, outcome: 'ok', detail: fields.join(',') || '(空)', caller })
      return { ok: true, site: args.site, fields, text: stdoutText(r) } as never
    },
  }))

  // ── 3. 生成强秘密（默认不显值） ──────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_generate',
    description:
      '生成强随机秘密（默认 24 字符、四类字符池、排除易混字符 lIO01）。'
      + '给了 site 就**直接写入**该条目（密码走 stdin，不进命令行参数），**默认不回显值**（reveal=true 才给）；'
      + '没给 site 时无从保存，故默认返回值。生成比「想一个」更安全——不要自己编密码。',
    parameters: {
      site: { type: 'string', description: '写入哪一条（省略 = 只生成不保存）' },
      user: { type: 'string', description: '用户名（写入时可选）' },
      length: { type: 'number', description: '长度（默认 24，范围 8-256）' },
      symbols: { type: 'boolean', description: '含符号（默认 true）' },
      digits: { type: 'boolean', description: '含数字（默认 true）' },
      reveal: { type: 'boolean', description: '是否回显明文（默认 false；无 site 时默认 true）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          site: { type: 'string' },
          saved: { type: 'boolean' },
          length: { type: 'number' },
          entropyBits: { type: 'number' },
          strength: { type: 'string' },
          masked: { type: 'string' },
          value: { type: 'string' },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(args: { site?: string; user?: string; length?: number; symbols?: boolean; digits?: boolean; reveal?: boolean }, exec: unknown) {
      const caller = callerOf(exec)
      const gen = generateSecret({ length: args.length ?? 24, symbols: args.symbols ?? true, digits: args.digits ?? true })
      const strength = estimateStrength(gen.value)
      const reveal = args.reveal ?? !args.site
      if (!args.site) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_generate', action: 'generate', outcome: 'ok', detail: `len=${gen.length} bits=${gen.entropyBits} 未保存`, caller })
        return {
          ok: true, length: gen.length, entropyBits: gen.entropyBits, strength: strength.label,
          masked: maskValue(gen.value), value: gen.value,
          text: `已生成（未保存）：len=${gen.length} ≈${gen.entropyBits} bits ${strength.label}`,
        } as never
      }
      const r = await runVault('set', { site: args.site, user: args.user, passwordStdin: true }, gen.value)
      if (r.code !== 0) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_generate', action: 'generate+set', site: args.site, outcome: 'failed', detail: classifyExit(r.code).kind, caller })
        return {
          ok: false, site: args.site, saved: false, length: gen.length, entropyBits: gen.entropyBits,
          strength: strength.label, masked: maskValue(gen.value), text: failure(r).text,
        } as never
      }
      appendTrace({ atMs: Date.now(), tool: 'passbook_generate', action: 'generate+set', site: args.site, field: 'password', outcome: 'ok', detail: `len=${gen.length} bits=${gen.entropyBits}`, caller })
      const base: Record<string, unknown> = {
        ok: true, site: args.site, saved: true, length: gen.length, entropyBits: gen.entropyBits,
        strength: strength.label, masked: maskValue(gen.value),
        text: `已生成并写入 site=${args.site}（len=${gen.length} ≈${gen.entropyBits} bits ${strength.label}，明文${reveal ? '已回显' : '未回显'}）`,
      }
      return (reveal ? { ...base, value: gen.value } : base) as never
    },
  }))

  // ── 4. 写入/更新字段（字段级合并） ───────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_set',
    description:
      '写入或更新一个条目的字段（**字段级合并**：只覆盖给到的字段，其余保留）。'
      + 'password 走 stdin（不进命令行、不进进程参数）；totp/recovery/notes/user 走参数（本机进程列表可见，属已知边界）。'
      + '写入后不回显明文。要新造强密码请用 passbook_generate，不要手打弱口令。',
    parameters: {
      site: { type: 'string', required: true, description: '条目 site 名' },
      user: { type: 'string', description: '用户名' },
      password: { type: 'string', description: '口令（走 stdin）' },
      totp: { type: 'string', description: 'TOTP 种子（base32）' },
      recovery: { type: 'string', description: '恢复码' },
      notes: { type: 'string', description: '备注（非密）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          site: { type: 'string' },
          fields: { type: 'array', items: { type: 'string' } },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(args: { site: string; user?: string; password?: string; totp?: string; recovery?: string; notes?: string }, exec: unknown) {
      const caller = callerOf(exec)
      const v = validateRequest('set', { site: args.site })
      if (!v.ok) return { ok: false, site: args.site, fields: [], text: v.error } as never
      const useStdin = typeof args.password === 'string' && args.password.length > 0
      const r = await runVault(
        'set',
        { site: args.site, user: args.user, totp: args.totp, recovery: args.recovery, notes: args.notes, passwordStdin: useStdin },
        useStdin ? args.password : undefined,
      )
      if (r.code !== 0) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_set', action: 'set', site: args.site, outcome: 'failed', detail: classifyExit(r.code).kind, caller })
        return { ok: false, site: args.site, fields: [], text: failure(r).text } as never
      }
      const out = stdoutText(r)
      const m = /字段=\[([^\]]*)\]/.exec(out)
      const fields = m?.[1] ? m[1].split(',').map((s) => s.trim()).filter(Boolean) : []
      appendTrace({ atMs: Date.now(), tool: 'passbook_set', action: 'set', site: args.site, outcome: 'ok', detail: `写入字段：[${fields.join(',')}]`, caller })
      return { ok: true, site: args.site, fields, text: out } as never
    },
  }))

  // ── 5. 取用（需显式确认 + 审计） ─────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_get',
    description:
      '取回某条目的一个字段值。**用于此刻的操作**，不是「看一眼」——值会进入会话记录。'
      + '秘密字段（password/totp/recovery）必须显式 confirm=true，否则拒绝并留审计。'
      + '若目标只是跑一条命令/登录，优先用 passbook_use（值不进上下文）。',
    parameters: {
      site: { type: 'string', required: true, description: '条目 site 名' },
      field: { type: 'string', description: '字段名（password/totp/recovery/notes/username，默认 password）' },
      confirm: { type: 'boolean', description: '取秘密字段必须为 true（显式确认用于此刻操作）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          site: { type: 'string' },
          field: { type: 'string' },
          value: { type: 'string' },
          strength: { type: 'string' },
          entropyBits: { type: 'number' },
          masked: { type: 'string' },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(args: { site: string; field?: PassField; confirm?: boolean }, exec: unknown) {
      const caller = callerOf(exec)
      const field = (args.field ?? 'password') as PassField
      const v = validateRequest('get', { site: args.site, field })
      if (!v.ok) return { ok: false, site: args.site, field, text: v.error } as never
      if (needsConfirmation(field) && args.confirm !== true) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_get', action: 'get', site: args.site, field, outcome: 'refused', detail: '未显式确认', caller })
        return { ok: false, site: args.site, field, text: `取 ${field} 会把明文交给调用方：确认要用于此刻操作后再加 confirm=true` } as never
      }
      const r = await runVault('get', { site: args.site, field, force: needsConfirmation(field) })
      if (r.code !== 0) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_get', action: 'get', site: args.site, field, outcome: 'failed', detail: classifyExit(r.code).kind, caller })
        return { ok: false, site: args.site, field, text: failure(r).text } as never
      }
      const value = r.stdout.replace(/\r?\n$/, '')
      const strength = field === 'password' ? estimateStrength(value) : null
      appendTrace({
        atMs: Date.now(), tool: 'passbook_get', action: 'get', site: args.site, field,
        outcome: 'ok', detail: `value len=${value.length}${strength ? ` fp=${fingerprint(value)}` : ''}`, caller,
      })
      const base: Record<string, unknown> = { ok: true, site: args.site, field, value, masked: maskValue(value) }
      if (strength) {
        base['strength'] = strength.label
        base['entropyBits'] = strength.entropyBits
      }
      base['text'] = `已取回 site=${args.site} field=${field}（len=${value.length}${strength ? ` ≈${strength.entropyBits} bits ${strength.label}` : ''}）`
      return base as never
    },
  }))

  // ── 6. 不泄漏地使用（env 注入） ──────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_use',
    description:
      '把某条目的字段值经**环境变量**注入子进程并执行命令，返回值与 stderr——秘密本身不回显（不进参数、不进上下文）。'
      + '子进程输出里若出现秘密值会被替换为 [redacted]。用于「拿 token 跑一条命令」「用口令登录」这类场景。',
    parameters: {
      site: { type: 'string', required: true, description: '条目 site 名' },
      field: { type: 'string', description: '字段名（默认 password）' },
      envName: { type: 'string', description: '注入的环境变量名（默认 PASSBOOK_SECRET）' },
      program: { type: 'string', required: true, description: '要执行的程序（如 curl.exe / node）' },
      args: { type: 'array', items: { type: 'string' }, description: '程序参数' },
      cwd: { type: 'string', description: '工作目录（可选）' },
      timeoutMs: { type: 'number', description: '超时毫秒（默认用插件配置）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          exitCode: { type: 'number' },
          program: { type: 'string' },
          stdout: { type: 'string' },
          stderr: { type: 'string' },
          redactionHits: { type: 'number' },
          timedOut: { type: 'boolean' },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(args: { site: string; field?: PassField; envName?: string; program: string; args?: string[]; cwd?: string; timeoutMs?: number }, exec: unknown) {
      const caller = callerOf(exec)
      const field = (args.field ?? 'password') as PassField
      const v = validateRequest('get', { site: args.site, field })
      if (!v.ok) return { ok: false, exitCode: -1, program: args.program, text: v.error } as never
      const got = await runVault('get', { site: args.site, field, force: needsConfirmation(field) })
      if (got.code !== 0) {
        appendTrace({ atMs: Date.now(), tool: 'passbook_use', action: 'use', site: args.site, field, outcome: 'failed', detail: `取值失败 ${classifyExit(got.code).kind}`, caller })
        return { ok: false, exitCode: -1, program: args.program, text: failure(got).text } as never
      }
      const secret = got.stdout.replace(/\r?\n$/, '')
      const envName = args.envName || 'PASSBOOK_SECRET'
      const timeoutMs = args.timeoutMs ?? config.timeoutMs
      const res = await new Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean }>((resolve) => {
        const child = spawn(args.program, args.args ?? [], {
          cwd: args.cwd,
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
          env: { ...process.env, [envName]: secret },
        })
        let out = ''
        let err = ''
        let settled = false
        const timer = setTimeout(() => {
          if (settled) return
          settled = true
          try { child.kill() } catch { /* 已退出 */ }
          resolve({ code: null, stdout: out, stderr: err, timedOut: true })
        }, timeoutMs)
        child.stdout.on('data', (d: Buffer) => { out += d.toString('utf8') })
        child.stderr.on('data', (d: Buffer) => { err += d.toString('utf8') })
        child.on('error', (e: Error) => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          resolve({ code: null, stdout: out, stderr: err + e.message, timedOut: false })
        })
        child.on('close', (code: number | null) => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          resolve({ code, stdout: out, stderr: err, timedOut: false })
        })
      })
      const rOut = redactSecrets(res.stdout, [secret])
      const rErr = redactSecrets(res.stderr, [secret])
      const hits = rOut.hits + rErr.hits
      const ok = res.code === 0 && !res.timedOut
      appendTrace({
        atMs: Date.now(), tool: 'passbook_use', action: 'use', site: args.site, field,
        outcome: ok ? 'ok' : 'failed',
        detail: `program=${args.program} exit=${res.code}${res.timedOut ? ' timeout' : ''} redactions=${hits} env=${envName}`,
        caller,
      })
      return {
        ok, exitCode: res.code ?? -1, program: args.program,
        stdout: rOut.text, stderr: rErr.text, redactionHits: hits, timedOut: res.timedOut,
        text: `${args.program} exit=${res.code ?? 'null'}${res.timedOut ? '（超时）' : ''}；秘密经 ${envName} 注入，输出脱敏 ${hits} 处`,
      } as never
    },
  }))

  // ── 7. 体检 ──────────────────────────────────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_audit',
    description:
      '密码本体检：久未轮换（默认 >180 天）、缺 password 字段、以及（deep=true 时）口令过弱与**同一口令复用**。'
      + 'deep 会真读值，但**只输出强度分档与哈希指纹，不输出任何值**。结论是提案不是动作——轮换/删除由我判断。',
    parameters: {
      deep: { type: 'boolean', description: '是否深检（读值算强度与复用；默认 false 只用元数据）' },
      rotationDays: { type: 'number', description: '轮换阈值天数（默认用插件配置 180）' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          total: { type: 'number' },
          deep: { type: 'boolean' },
          reusedGroups: { type: 'number' },
          findings: { type: 'array', items: { type: 'string' } },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(args: { deep?: boolean; rotationDays?: number }, exec: unknown) {
      const caller = callerOf(exec)
      const r = await runVault('list-json')
      if (r.code !== 0) return { ok: false, total: 0, deep: false, reusedGroups: 0, findings: [], text: failure(r).text } as never
      const parsed = parseVaultListJson(r.stdout)
      if (!parsed.ok) return { ok: false, total: 0, deep: false, reusedGroups: 0, findings: [], text: parsed.error } as never
      const entries: VaultEntryMeta[] = parsed.entries
      const deep = args.deep === true
      const values: Record<string, { password?: string }> = {}
      const plainFields: Record<string, { notes?: string }> = {}
      if (deep) {
        for (const e of entries) {
          if (e.fields.includes('password')) {
            const got = await runVault('get', { site: e.site, field: 'password', force: true })
            if (got.code === 0) values[e.site] = { password: got.stdout.replace(/\r?\n$/, '') }
          }
          // notes 是**非密字段**（不需 -Force）⇒ 顺带扫「秘密是否躺在无闸门字段里」。
          // 命中只记形状，不记值（值不进报告、不进轨迹）。
          if (e.fields.includes('notes')) {
            const gotNotes = await runVault('get', { site: e.site, field: 'notes' })
            if (gotNotes.code === 0) plainFields[e.site] = { notes: gotNotes.stdout.replace(/\r?\n$/, '') }
          }
        }
      }
      const report = planAudit(entries, values, { rotationDays: args.rotationDays ?? config.rotationDays, deep, plainFields })
      const findings = report.findings.map((f) => `${f.kind}: ${f.site} — ${f.detail}`)
      appendTrace({
        atMs: Date.now(), tool: 'passbook_audit', action: 'audit', outcome: 'ok',
        detail: `total=${report.total} findings=${findings.length} deep=${deep} reused=${report.reusedGroups}`, caller,
      })
      return {
        ok: true, total: report.total, deep, reusedGroups: report.reusedGroups, findings,
        text: findings.length === 0 ? `体检通过：${report.total} 条无异常` : `${report.total} 条中 ${findings.length} 项发现`,
      } as never
    },
  }))

  // ── 8. 端到端自检（临时库，绝不碰真库） ──────────────────────────────────
  ctx.tools.register(defineTool({
    name: 'passbook_selftest',
    description:
      '端到端自检：在**临时 vault**（-VaultPath 隔离）上跑 init→set→get→verify→list-json→remove 全链路，'
      + '验证「脚本存在、DPAPI 可加解密、字段合并、stdin 通道、结构化输出、删除、退出码语义」都真能工作。'
      + '**绝不触碰真库**（夹具隔离纪律：测试不碰生产资产）。改过机制或 vault.ps1 后跑它。',
    parameters: {},
    output: {
      schema: {
        type: 'object', additionalProperties: false, properties: {
          ok: { type: 'boolean', required: true },
          passed: { type: 'number' },
          total: { type: 'number' },
          steps: { type: 'array', items: { type: 'string' } },
          text: { type: 'string' },
        },
      },
      render: textOut,
    },
    async execute(_args: Record<string, unknown>, exec: unknown) {
      const caller = callerOf(exec)
      const dir = join(tmpdir(), `passbook-selftest-${randomUUID()}`)
      const vaultPath = join(dir, 'selftest.vault')
      const steps: string[] = []
      let passed = 0
      const record = (label: string, ok: boolean, detail = ''): void => {
        steps.push(`${ok ? 'PASS' : 'FAIL'} · ${label}${detail ? ` — ${detail}` : ''}`)
        if (ok) passed++
      }
      const T = 'selftest-site'
      const PW = 'Zq7!mR4#vT9@kL2$wN8^pB6&'
      try {
        record('vault.ps1 存在', existsSync(config.vaultScript), config.vaultScript)

        const init = await runVault('init', { vaultPath })
        record('init 建库', init.code === 0, stdoutText(init) || init.stderr.trim())

        const setRes = await runVault('set', { site: T, user: 'selftest', passwordStdin: true, notes: 'self-test entry', vaultPath }, PW)
        record('set 写入（password 走 stdin）', setRes.code === 0, stdoutText(setRes))

        const getRes = await runVault('get', { site: T, field: 'password', force: true, vaultPath })
        record('get 取回（密文往返一致）', getRes.code === 0 && getRes.stdout.replace(/\r?\n$/, '') === PW, getRes.code === 0 ? `len=${getRes.stdout.trim().length}` : getRes.stderr.trim())

        const mergeRes = await runVault('set', { site: T, totp: 'JBSWY3DPEHPK3PXP', vaultPath })
        const afterMerge = await runVault('get', { site: T, field: 'fields', vaultPath })
        record('set 字段合并（password 未被抹掉）', mergeRes.code === 0 && /password/.test(afterMerge.stdout), stdoutText(afterMerge))

        const verifyRes = await runVault('verify', { vaultPath })
        record('verify 健康', verifyRes.code === 0, stdoutText(verifyRes))

        const listRes = await runVault('list-json', { vaultPath })
        const parsed = parseVaultListJson(listRes.stdout)
        record('list-json 可解析', listRes.code === 0 && parsed.ok && (!parsed.ok || parsed.entries.length === 1), parsed.ok ? `${parsed.entries.length} 条` : parsed.error)

        const rmRes = await runVault('remove', { site: T, vaultPath })
        const listAfter = await runVault('list-json', { vaultPath })
        const parsedAfter = parseVaultListJson(listAfter.stdout)
        record('remove 删除', rmRes.code === 0 && parsedAfter.ok && (!parsedAfter.ok || parsedAfter.entries.length === 0), stdoutText(rmRes))

        const missing = await runVault('get', { site: 'no-such-site', field: 'fields', vaultPath })
        record('无此条目 → 退出码 6（语义可辨，不掩盖）', missing.code === 6, `code=${missing.code} kind=${classifyExit(missing.code).kind}`)

        const noForce = await runVault('get', { site: T, field: 'password', vaultPath })
        record('秘密字段无 -Force → 拒绝', missing.code === 6 && noForce.code !== 0, `code=${noForce.code} kind=${classifyExit(noForce.code).kind}`)

        record('夹具隔离（-VaultPath 指向临时目录）', vaultPath.startsWith(tmpdir()), vaultPath)
      } catch (err) {
        record('自检异常', false, String(err))
      } finally {
        try { rmSync(dir, { recursive: true, force: true }) } catch { /* 清理失败不影响结论 */ }
      }
      const total = steps.length
      const ok = passed === total
      appendTrace({ atMs: Date.now(), tool: 'passbook_selftest', action: 'selftest', outcome: ok ? 'ok' : 'failed', detail: `${passed}/${total}`, caller })
      return { ok, passed, total, steps, text: `自检 ${passed}/${total} ${ok ? '通过' : '有失败项'}` } as never
    },
  }))

  logger.info(`passbook 已装载：vault=${config.vaultPath || '(脚本默认)'} trace=${traceFile}`)
}

/** 从 exec 里取调用者会话标识（形状未知时安全降级——不影响主流程）。 */
function callerOf(exec: unknown): string | undefined {
  const e = exec as { agent?: { sessionId?: string; id?: string } } | undefined
  const id = e?.agent?.sessionId ?? e?.agent?.id
  return typeof id === 'string' && id.length > 0 ? id : undefined
}

/** 供测试与文档引用：字段全集（避免「文档说 A、实现是 B」）。 */
export const FIELDS = ALL_FIELDS
