/**
 * 契约测试（源码级）：防「render 签名写错」这类只在运行时显形的陷阱。
 *
 * 事故（2026-09-17 实测）：`textOut` 写成单参 `(v) => JSON.stringify(v)`，
 * 而 dsh-tools 的 render 契约是 `(args, value)` ⇒ 渲染出的是**参数**而不是返回值：
 * 工具调用显示 `{}`，而审计轨迹显示 `ok · 25 条`（工具其实成功了）。
 * 教训：显示层骗人时，看**机制自证的落盘证据**；同时把契约钉成可测断言。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

test('契约：textOut 必须是 (args, value) 两参——第二参才是返回值', () => {
  const decl = /const textOut = \(([^)]*)\)/.exec(SRC)
  assert.ok(decl, '找不到 textOut 声明')
  const params = decl[1].split(',').map((s) => s.trim()).filter(Boolean)
  assert.equal(params.length, 2, `textOut 应为两参，实际 ${params.length} 个：${decl[1]}`)
  assert.match(params[1], /^value/, '第二参必须命名为 value（即返回值）')
  assert.match(params[0], /^_?args/, '第一参是参数（可加下划线前缀表示未使用）')
})

test('契约：所有工具的 render 统一走 textOut（不得另写单参 render）', () => {
  const renders = [...SRC.matchAll(/render:\s*([A-Za-z_$][\w$]*)/g)].map((m) => m[1])
  assert.ok(renders.length >= 8, `应至少有 8 处 render，实际 ${renders.length}`)
  const names = [...new Set(renders)]
  assert.deepEqual(names, ['textOut'], `render 必须统一走 textOut，实际：${names.join(',')}`)
})

test('契约：8 个工具全部注册且名称前缀一致', () => {
  const names = [...SRC.matchAll(/name:\s*'(passbook_[a-z]+)'/g)].map((m) => m[1])
  const expected = [
    'passbook_list', 'passbook_fields', 'passbook_generate', 'passbook_set',
    'passbook_get', 'passbook_use', 'passbook_audit', 'passbook_selftest',
  ]
  assert.deepEqual([...names].sort(), [...expected].sort())
})

test('契约：秘密绝不进入子进程 argv（源码级检查——password 只以 stdin 标记出现）', () => {
  assert.ok(SRC.includes('passwordStdin'), 'password 必须走 stdin 标记')
  // 禁止把 args.password 直接拼进 argv 的写法
  assert.ok(!/push\([^)]*args\.password/.test(SRC), 'argv 构造中不得出现 args.password')
  assert.ok(!/argv[^\n]*args\.password/.test(SRC), 'argv 变量中不得拼接 args.password')
})

test('契约：观测不反噬——appendTrace 必须包 try/catch 并返回 boolean', () => {
  const fn = /function appendTrace\([\s\S]*?\n  \}/.exec(SRC)
  assert.ok(fn, '找不到 appendTrace')
  assert.ok(fn[0].includes('try {'), 'appendTrace 必须包 try')
  assert.ok(fn[0].includes('catch'), 'appendTrace 必须有 catch')
  assert.ok(/return (true|false)/.test(fn[0]), 'appendTrace 必须返回 boolean')
})

test('契约：临时库隔离——selftest 必须使用 -VaultPath 且删净', () => {
  const selftest = /passbook_selftest[\s\S]*?logger\.info/.exec(SRC)
  assert.ok(selftest, '找不到 selftest 段')
  assert.ok(selftest[0].includes('vaultPath'), 'selftest 必须传 -VaultPath')
  assert.ok(selftest[0].includes('rmSync'), 'selftest 必须清理临时库')
  assert.ok(selftest[0].includes('tmpdir()'), 'selftest 必须在临时目录工作')
})
