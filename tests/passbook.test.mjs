/**
 * dsh-passbook 单测（node --test，跑构建产物 lib/passbook.js）
 *
 * 判据纪律：不只测 happy path，重点测**隐私不变量**（值不得出现在报告/掩码/轨迹里）
 * 与**语义精确性**（退出码不互相掩盖；解析失败不得静默给空数组）。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ALL_FIELDS,
  SECRET_FIELDS,
  ageDays,
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
} from '../lib/passbook.js'

const JSON_ENTRY = (site, fields, updatedAt = new Date().toISOString()) =>
  JSON.stringify([{ site, username: 'u', fields, updatedAt }])

// ── 生成 ────────────────────────────────────────────────────────────────────
test('generateSecret：默认 24 字符、四类池全覆盖、熵 ≥ 100 bits', () => {
  const g = generateSecret()
  assert.equal(g.length, 24)
  assert.equal(g.value.length, 24)
  assert.ok(/[a-z]/.test(g.value), '含小写')
  assert.ok(/[A-Z]/.test(g.value), '含大写')
  assert.ok(/[0-9]/.test(g.value), '含数字')
  assert.ok(/[^A-Za-z0-9]/.test(g.value), '含符号')
  assert.ok(g.entropyBits >= 100, `熵 ${g.entropyBits} 应 ≥ 100`)
})

test('generateSecret：默认排除易混字符 l I O 0 1', () => {
  for (let i = 0; i < 200; i++) {
    const { value } = generateSecret()
    for (const ch of ['l', 'I', 'O', '0', '1']) {
      assert.ok(!value.includes(ch), `第 ${i} 次出现易混字符 ${ch}`)
    }
  }
})

test('generateSecret：长度钳制 8-256', () => {
  assert.equal(generateSecret({ length: 3 }).length, 8)
  assert.equal(generateSecret({ length: 9999 }).length, 256)
  assert.equal(generateSecret({ length: 32.9 }).length, 32)
})

test('generateSecret：200 次无重复（随机性下限）', () => {
  const seen = new Set()
  for (let i = 0; i < 200; i++) seen.add(generateSecret().value)
  assert.equal(seen.size, 200)
})

test('generateSecret：全部类别关闭时仍有可用池（不抛空池）', () => {
  const g = generateSecret({ lower: false, upper: false, digits: false, symbols: false })
  assert.equal(g.value.length, 24)
})

test('generateSecret：关掉符号则不出符号', () => {
  const g = generateSecret({ symbols: false, length: 40 })
  assert.ok(/^[A-Za-z0-9]+$/.test(g.value))
})

// ── 强度 ────────────────────────────────────────────────────────────────────
test('estimateStrength：分档判据正确', () => {
  assert.equal(estimateStrength('password').label, 'weak')
  assert.equal(estimateStrength('abc').label, 'weak')
  assert.equal(estimateStrength('Zq7!mR4#vT9@kL2$wN8^pB6&').label, 'very-strong')
  const mid = estimateStrength('Tr0ub4dor&3xYz')
  assert.ok(['fair', 'strong'].includes(mid.label), `实际 ${mid.label}`)
})

test('estimateStrength：字符类别影响字符池估计', () => {
  assert.equal(estimateStrength('abcdefgh').charsetSize, 26)
  assert.equal(estimateStrength('abcdEFGH').charsetSize, 52)
  assert.equal(estimateStrength('abcd1234').charsetSize, 36)
  assert.ok(estimateStrength('ab!@#$%^').charsetSize > 36)
})

// ── 掩码与脱敏（隐私不变量） ────────────────────────────────────────────────
test('maskValue：不含原值任何字符，且给出长度', () => {
  const secret = 'Zq7!mR4#vT9@kL2$wN8^pB6&'
  const masked = maskValue(secret)
  assert.ok(!masked.includes(secret))
  for (const ch of secret.slice(0, 5)) assert.ok(!masked.includes(ch), `掩码漏出字符 ${ch}`)
  assert.ok(masked.includes('24'))
})

test('redactSecrets：原文 / URL 编码 / base64 三种形态都替换', () => {
  const secret = 'Zq7!mR4#vT9@kL2$wN8^pB6&'
  const enc = encodeURIComponent(secret)
  const b64 = Buffer.from(secret, 'utf8').toString('base64')
  const text = `a=${secret} b=${enc} c=${b64}`
  const r = redactSecrets(text, [secret])
  assert.ok(!r.text.includes(secret))
  assert.ok(!r.text.includes(b64))
  assert.ok(r.hits >= 3, `命中 ${r.hits} 处应 ≥ 3`)
  assert.ok(r.text.includes('[redacted]'))
})

test('redactSecrets：无命中时原样返回且 hits=0', () => {
  const r = redactSecrets('hello world', ['Zq7!mR4#vT9@kL2'])
  assert.equal(r.text, 'hello world')
  assert.equal(r.hits, 0)
})

test('redactSecrets：过短值（<4）跳过，避免误伤正常文本', () => {
  const r = redactSecrets('the cat sat', ['cat', 'a'])
  assert.equal(r.text, 'the cat sat')
  assert.equal(r.hits, 0)
})

test('fingerprint：稳定、定长、不同值不同指纹', () => {
  const a = fingerprint('secret-one')
  const b = fingerprint('secret-two')
  assert.equal(a.length, 12)
  assert.equal(a, fingerprint('secret-one'))
  assert.notEqual(a, b)
})

// ── 退出码语义 ──────────────────────────────────────────────────────────────
test('classifyExit：六个场景语义互不掩盖', () => {
  assert.equal(classifyExit(0).kind, 'ok')
  assert.equal(classifyExit(2).kind, 'vault-missing')
  assert.equal(classifyExit(3).kind, 'decrypt-failed')
  assert.equal(classifyExit(4).kind, 'parse-failed')
  assert.equal(classifyExit(5).kind, 'structure-mismatch')
  assert.equal(classifyExit(6).kind, 'param-or-entry')
  assert.equal(classifyExit(null).kind, 'unknown')
  assert.equal(classifyExit(99).kind, 'unknown')
  const meanings = [2, 3, 4, 5, 6].map((c) => classifyExit(c).meaning)
  assert.equal(new Set(meanings).size, 5, '五种失败的说明必须各不相同')
})

// ── list-json 解析 ──────────────────────────────────────────────────────────
test('parseVaultListJson：正常单行 JSON', () => {
  const r = parseVaultListJson(JSON_ENTRY('github', 'password,totp'))
  assert.equal(r.ok, true)
  assert.equal(r.entries.length, 1)
  assert.deepEqual(r.entries[0].fields, ['password', 'totp'])
})

test('parseVaultListJson：容忍前后混入警告文本与 BOM', () => {
  const raw = '\uFEFF警告：something happened\n' + JSON_ENTRY('github', 'password') + '\ntrailing noise'
  const r = parseVaultListJson(raw)
  assert.equal(r.ok, true)
  assert.equal(r.entries[0].site, 'github')
})

test('parseVaultListJson：空数组合法', () => {
  const r = parseVaultListJson('[]')
  assert.equal(r.ok, true)
  assert.equal(r.entries.length, 0)
})

test('parseVaultListJson：垃圾输入 → 明确错误（不静默给空数组）', () => {
  const r = parseVaultListJson('vault: 解密失败（DPAPI）')
  assert.equal(r.ok, false)
  assert.ok(r.error.includes('找不到可解析的 JSON 数组'))
})

test('parseVaultListJson：对象而非数组 → 错误', () => {
  const r = parseVaultListJson('{"site":"x"}')
  assert.equal(r.ok, false)
})

// ── argv 构造（秘密不得入参数） ─────────────────────────────────────────────
test('buildVaultArgs：秘密值绝不出现在 argv（stdin 通道）', () => {
  const secret = 'Zq7!mR4#vT9@kL2$wN8^pB6&'
  const args = buildVaultArgs('set', { site: 'github', user: 'alice', passwordStdin: true })
  assert.ok(args.includes('-PasswordStdin'))
  assert.ok(args.includes('github'))
  for (const a of args) assert.ok(!a.includes(secret), `argv 泄漏秘密：${a}`)
  assert.equal(args.filter((a) => a.includes('-Password')).length, 1)
})

test('buildVaultArgs：vaultPath / field / force 正确透传', () => {
  const args = buildVaultArgs('get', { site: 's', field: 'totp', force: true, vaultPath: 'C:/tmp/x.vault' })
  assert.ok(args.includes('-VaultPath'))
  assert.ok(args.includes('C:/tmp/x.vault'))
  assert.ok(args.includes('-Field'))
  assert.ok(args.includes('totp'))
  assert.ok(args.includes('-Force'))
  assert.equal(args[0], '-NoProfile')
  assert.ok(args.includes('@SCRIPT@'), '脚本路径用占位符，由调用方替换')
})

test('buildVaultArgs：不给密码时不得出现 -PasswordStdin', () => {
  const args = buildVaultArgs('set', { site: 's', totp: 'ABC' })
  assert.ok(!args.includes('-PasswordStdin'))
})

// ── 请求校验 ────────────────────────────────────────────────────────────────
test('validateRequest：缺 site 报错；未知字段报错；合法通过', () => {
  assert.equal(validateRequest('set', {}).ok, false)
  assert.equal(validateRequest('get', { site: 'x' }).ok, true)
  assert.equal(validateRequest('get', { site: 'x', field: 'nope' }).ok, false)
  assert.equal(validateRequest('get', { site: 'x', field: 'fields' }).ok, true)
  const err = validateRequest('get', { site: 'x', field: 'nope' })
  assert.ok(!err.ok && err.error.includes('未知字段'))
})

test('字段集：ALL_FIELDS 与 SECRET_FIELDS 的关系明确', () => {
  assert.deepEqual([...SECRET_FIELDS].sort(), ['password', 'recovery', 'totp'])
  for (const f of SECRET_FIELDS) assert.ok(ALL_FIELDS.includes(f))
  assert.equal(needsConfirmation('password'), true)
  assert.equal(needsConfirmation('totp'), true)
  assert.equal(needsConfirmation('recovery'), true)
  assert.equal(needsConfirmation('notes'), false)
  assert.equal(needsConfirmation('username'), false)
})

// ── 体检（提案，不动作） ────────────────────────────────────────────────────
const ENTRIES = [
  { site: 'fresh', username: 'a', fields: ['password'], updatedAt: new Date().toISOString() },
  { site: 'stale', username: 'b', fields: ['password'], updatedAt: '2020-01-01T00:00:00.000Z' },
  { site: 'no-pw', username: 'c', fields: ['notes'], updatedAt: new Date().toISOString() },
]

test('planAudit：陈旧与无凭据字段都能检出（recovery-only 不误报）', () => {
  const entries = [
    ...ENTRIES,
    { site: 'recovery-only', username: 'd', fields: ['recovery'], updatedAt: new Date().toISOString() },
  ]
  const r = planAudit(entries, {}, { nowMs: Date.parse('2026-09-17T00:00:00Z'), rotationDays: 180 })
  const kinds = r.findings.map((f) => `${f.kind}:${f.site}`)
  assert.ok(kinds.includes('stale:stale'))
  assert.ok(kinds.includes('no-credential:no-pw'))
  assert.ok(!kinds.includes('stale:fresh'))
  assert.ok(!kinds.some((k) => k.includes('recovery-only')), 'recovery-only 条目不得被判「无凭据」——它本就该只有 recovery（语义精确）')
  assert.equal(r.deep, false)
})

test('planAudit：deep 检出「秘密躺在无闸门字段里」（只报形状，不报值）', () => {
  const token = 'api-token=abcdefghijklmnopqrstuvwxyz0123456789ABCD'
  const entries = [{ site: 'cloudflare-api', username: '', fields: ['notes'], updatedAt: new Date().toISOString() }]
  const r = planAudit(entries, {}, { deep: true, plainFields: { 'cloudflare-api': { notes: token } } })
  const f = r.findings.find((x) => x.kind === 'secret-in-ungated-field')
  assert.ok(f, '应检出无闸门字段里的秘密')
  assert.ok(!JSON.stringify(r).includes(token), '体检报告泄漏了字段内容')
  const clean = planAudit(entries, {}, { deep: true, plainFields: { 'cloudflare-api': { notes: '普通备注：注册于 2026-09-16' } } })
  assert.ok(!clean.findings.some((x) => x.kind === 'secret-in-ungated-field'), '普通备注不得误报')
})

test('planAudit：浅层不得要求值（values 为空也不报错）', () => {
  const r = planAudit(ENTRIES)
  assert.equal(r.reusedGroups, 0)
  assert.ok(r.findings.every((f) => f.kind !== 'weak' && f.kind !== 'reused'))
})

test('planAudit：deep 检出弱口令', () => {
  const values = { fresh: { password: 'password' } }
  const r = planAudit([ENTRIES[0]], values, { deep: true })
  const weak = r.findings.find((f) => f.kind === 'weak')
  assert.ok(weak, '应检出弱口令')
  assert.equal(weak.site, 'fresh')
})

test('planAudit：deep 检出复用（且报告里不得出现任何口令值）', () => {
  const shared = 'Zq7!mR4#vT9@kL2$wN8^pB6&'
  const entries = [
    { site: 'a', username: 'x', fields: ['password'], updatedAt: new Date().toISOString() },
    { site: 'b', username: 'y', fields: ['password'], updatedAt: new Date().toISOString() },
  ]
  const r = planAudit(entries, { a: { password: shared }, b: { password: shared } }, { deep: true })
  assert.equal(r.reusedGroups, 1)
  const reused = r.findings.find((f) => f.kind === 'reused')
  assert.ok(reused && reused.site.includes('a') && reused.site.includes('b'))
  const serialized = JSON.stringify(r)
  assert.ok(!serialized.includes(shared), '体检报告泄漏了口令值')
  assert.ok(serialized.includes(fingerprint(shared)), '应以指纹代替值')
})

test('planAudit：不同口令不误报复用', () => {
  const entries = [
    { site: 'a', username: 'x', fields: ['password'], updatedAt: new Date().toISOString() },
    { site: 'b', username: 'y', fields: ['password'], updatedAt: new Date().toISOString() },
  ]
  const r = planAudit(entries, { a: { password: 'Zq7!mR4#vT9@kL2$wN8^pB6&' }, b: { password: 'Xy9$kT2!nQ7@mW4#vB6^pL8&' } }, { deep: true })
  assert.equal(r.reusedGroups, 0)
})

test('ageDays：坏日期返回 null（不假装知道）', () => {
  assert.equal(ageDays('', Date.now()), null)
  assert.equal(ageDays('not-a-date', Date.now()), null)
  assert.ok(Math.abs(ageDays(new Date().toISOString(), Date.now())) < 0.01)
})

// ── 轨迹（不含值） ──────────────────────────────────────────────────────────
test('traceLine：可解析、含 iso、且**不含 value 键**', () => {
  const line = traceLine({ atMs: 1_700_000_000_000, tool: 'passbook_get', action: 'get', site: 'github', field: 'password', outcome: 'ok', detail: 'len=24', caller: 'sess-1' })
  const parsed = JSON.parse(line)
  assert.equal(parsed.tool, 'passbook_get')
  assert.equal(parsed.site, 'github')
  assert.equal(parsed.outcome, 'ok')
  assert.ok(parsed.iso.startsWith('2023-'))
  assert.ok(!('value' in parsed), '轨迹不得含 value 键')
  assert.ok(!line.includes('\n'))
})

test('traceLine：可选字段缺省时不出现键（无损 JSON 纪律）', () => {
  const parsed = JSON.parse(traceLine({ atMs: 0, tool: 't', action: 'a', outcome: 'ok' }))
  assert.ok(!('site' in parsed))
  assert.ok(!('field' in parsed))
  assert.ok(!('detail' in parsed))
  assert.ok(!('caller' in parsed))
})
