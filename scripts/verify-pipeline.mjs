/**
 * verify-pipeline.mjs — 端到端验证「插件 ↔ vault.ps1」的真实接缝（不依赖 DSH 装载）。
 *
 * 复用 lib/passbook.js 的 argv 构造与退出码语义，直接驱动 powershell.exe，
 * 在**临时 vault**（-VaultPath 隔离）上跑完整链路。绝不触碰真库。
 *
 * 用法：node scripts/verify-pipeline.mjs
 */
import { spawn } from 'node:child_process'
import { existsSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { randomUUID } from 'node:crypto'
import { buildVaultArgs, classifyExit, parseVaultListJson } from '../lib/passbook.js'

const SCRIPT = process.env['PASSBOOK_VAULT_SCRIPT']
  || 'E:\\alice\\projects\\self\\alice-identity\\scripts\\vault.ps1'
const T = 'verify-pipeline-site'
const PW = 'Zq7!mR4#vT9@kL2$wN8^pB6&'

function run(action, params = {}, stdin) {
  const argv = buildVaultArgs(action, params).map((a) => (a === '@SCRIPT@' ? SCRIPT : a))
  return new Promise((resolve) => {
    const child = spawn('powershell.exe', argv, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    child.stdout.on('data', (d) => { out += d.toString('utf8') })
    child.stderr.on('data', (d) => { err += d.toString('utf8') })
    child.on('error', (e) => resolve({ code: null, stdout: out, stderr: err + e.message }))
    child.on('close', (code) => resolve({ code, stdout: out, stderr: err }))
    if (stdin !== undefined) child.stdin.write(stdin, 'utf8')
    child.stdin.end()
  })
}

const steps = []
let passed = 0
const record = (label, ok, detail = '') => {
  steps.push(`${ok ? 'PASS' : 'FAIL'} · ${label}${detail ? ` — ${detail}` : ''}`)
  if (ok) passed++
}

const dir = join(tmpdir(), `passbook-verify-${randomUUID()}`)
const vaultPath = join(dir, 'verify.vault')

try {
  record('vault.ps1 存在', existsSync(SCRIPT), SCRIPT)

  const init = await run('init', { vaultPath })
  record('init 建库', init.code === 0, (init.stdout || init.stderr).trim())

  const set = await run('set', { site: T, user: 'verify', passwordStdin: true, notes: 'pipeline verify', vaultPath }, PW)
  record('set 写入（password 走 stdin，不进参数）', set.code === 0, set.stdout.trim())
  record('set 输出不回显明文', !set.stdout.includes(PW) && !set.stderr.includes(PW), '（明文不回显）')

  const get = await run('get', { site: T, field: 'password', force: true, vaultPath })
  record('get 取回且与写入逐字符一致', get.code === 0 && get.stdout.replace(/\r?\n$/, '') === PW, `code=${get.code} len=${get.stdout.trim().length}`)

  const noForce = await run('get', { site: T, field: 'password', vaultPath })
  record('秘密字段无 -Force → 拒绝（闸门真会拦）', noForce.code === 6 && /-Force/.test(noForce.stderr), `code=${noForce.code} kind=${classifyExit(noForce.code).kind}`)

  const merge = await run('set', { site: T, totp: 'JBSWY3DPEHPK3PXP', vaultPath })
  const fields = await run('get', { site: T, field: 'fields', vaultPath })
  record('set 字段合并（password 未被抹掉）', merge.code === 0 && /password/.test(fields.stdout) && /totp/.test(fields.stdout), fields.stdout.trim())

  const verify = await run('verify', { vaultPath })
  record('verify 健康', verify.code === 0, verify.stdout.trim())

  const listJson = await run('list-json', { vaultPath })
  const parsed = parseVaultListJson(listJson.stdout)
  record('list-json 可解析且条目数正确', listJson.code === 0 && parsed.ok && parsed.entries.length === 1, parsed.ok ? `${parsed.entries.length} 条 / fields=[${parsed.entries[0].fields.join(',')}]` : parsed.error)

  const missing = await run('get', { site: 'no-such-site', field: 'fields', vaultPath })
  record('无此条目 → 退出码 6（语义可辨）', missing.code === 6, `code=${missing.code} kind=${classifyExit(missing.code).kind}`)

  const rm = await run('remove', { site: T, vaultPath })
  const after = await run('list-json', { vaultPath })
  const parsedAfter = parseVaultListJson(after.stdout)
  record('remove 删除干净', rm.code === 0 && parsedAfter.ok && parsedAfter.entries.length === 0, rm.stdout.trim())

  const garbage = await run('get', { site: 'x', field: 'not-a-field', vaultPath })
  record('未知字段 → 退出码 6', garbage.code === 6, `code=${garbage.code}`)

  record('夹具隔离：全程 -VaultPath 指向临时目录', vaultPath.startsWith(tmpdir()), vaultPath)
} catch (err) {
  record('验证脚本异常', false, String(err))
} finally {
  try { rmSync(dir, { recursive: true, force: true }) } catch { /* 清理失败不影响结论 */ }
}

for (const s of steps) console.log(s)
console.log(`\n结果：${passed}/${steps.length} ${passed === steps.length ? '通过' : '有失败项'}`)
process.exit(passed === steps.length ? 0 : 1)
