# dsh-passbook 语义文档 v0.1 — 隐私密码本

> 版本 v0.1 · 2026-09-17 · 作者：爱丽丝 · 状态：**已实现（8 工具 + 纯逻辑层 + 轨迹 + 端到端自检；验收 15/17，见 §7）**
> 开发模式：语义文档优先——先写下「它应当是什么」，再让实现逼近，最后由实践回修本文档。
> 实现落点：`self-plugins/dsh-passbook/src/passbook.ts`（纯逻辑）+ `src/index.ts`（工具层）+ `scripts/verify-pipeline.mjs`（端到端）。
> 存储真源：`projects/self/alice-identity/scripts/vault.ps1`（**本插件不写另一份库**）。

---

## 0 · 文档自身的协议

1. `[MUST]` 硬性契约 / `[SHOULD]` 默认应遵守 / `[待逼近]` 未实现或未验证 / `[待定]` 需主人裁决。
2. **未验证不得写成已实现**：任何「已支持/已验证」必须能在 §7 找到判据与证据（命令 + 输出摘录）。
3. 冲突先登记（§8 偏离日志），再决定改代码还是改文档。
4. 文档版本 = 插件 minor 锚（v0.1 文档 ↔ 0.1.x）。

---

## 1 · 定位与反定位

**一句话**：密码本是**我自己的私密凭据操作面**——把「生成 / 写入 / 取用 / 使用 / 体检」这些动作变成有闸门、有审计、有证据的工具调用。

**它是什么**：凭据操作面 · 秘密闸门（秘密字段需显式确认）· 隐私纪律执行者（掩码/脱敏/指纹）· 自证机制（端到端自检工具）。

**它不是什么（负边界）**：
- ❌ 不是新存储：库只有一个（DPAPI vault），本插件只构造 argv 与判读退出码。
- ❌ 不是保险箱 / 沙箱：与宿主同进程同权限，纪律是**工程约束**不是技术强制。
- ❌ 不是主人的密码管理器：主人侧凭据归主人的单一来源（`.credentials.yaml`），**不得混入**。
- ❌ 不是「看一眼」的工具：`passbook_get` 的语义是**用于此刻的操作**（值会进会话记录）。

---

## 2 · 术语

| 术语 | 语义 | 谁拥有 |
|---|---|---|
| **条目（entry）** | vault 中一个 `site` 的记录（username/password/totp/recovery/notes） | vault.ps1 |
| **秘密字段** | `password` / `totp` / `recovery`——取用需显式确认 | 本插件判定 |
| **非密字段** | `notes` / `username`——可直接读 | vault.ps1 已实现（`-Force` 只管秘密字段） |
| **确认（confirm）** | 调用方对「我此刻要用它」的显式声明 | 调用方（我） |
| **注入使用（use）** | 值经子进程 env 进入目标程序，不回显 | 本插件 |
| **脱敏（redact）** | 输出里出现秘密值时替换为 `[redacted]` | 本插件 |
| **指纹（fingerprint）** | 值的 sha256 前 12 位——用于「是否复用」而不泄漏值 | 本插件 |
| **审计轨迹** | 只记「谁·何时·对哪条·做了什么·结果」的 JSONL | 本插件 |

---

## 3 · 概念模型与不变量

```
      我（调用方）
         │  ①生成/写入（password 走 stdin）
         ▼
   passbook 工具层 ──argv──▶ powershell.exe ──▶ vault.ps1 ──DPAPI──▶ alice-identity.vault
         │  ②取用（秘密须 confirm）                                   （唯一真源）
         │  ③使用（值→子进程 env，stdout/stderr 脱敏）
         └──▶ 审计轨迹 <DSH_HOME>/passbook-trace.jsonl（永不含值）
```

**不变量（MUST）**
- **I1 单一真源**：只有一份库；本插件不得写第二份存储。
- **I2 值最小暴露**：秘密不得进入①命令行参数（password 走 stdin）②会话上下文（`use` 走 env）③审计轨迹（永不含值）。
- **I3 闸门真实**：秘密字段无 `confirm` 必被拒绝，且留下 `refused` 记录（不是静默失败）。
- **I4 语义可辨**：vault 的 6 类退出码 → 语义一一对应，不互相掩盖（vault 不存在 ≠ 解密失败 ≠ 解析失败 ≠ 结构不符 ≠ 参数/条目问题）。
- **I5 观测不反噬**：轨迹写失败只返回 `false`，绝不抛。
- **I6 夹具隔离**：任何测试/自检**不得触碰真库**（一律 `-VaultPath` 指向临时文件）。
- **I7 不假装知道**：解析失败返回明确错误，**不得**静默给空结果（空数组 ≠ 解析失败）。

---

## 4 · 契约

### 4.1 工具（8 个，模型可见面）

| 工具 | 输入要点 | 输出要点 | 副作用 |
|---|---|---|---|
| `passbook_list` | — | `count` / `entries[]`（site·user·字段·更新时间） | 读库、写轨迹 |
| `passbook_fields` | `site` | `fields[]` | 读库、写轨迹 |
| `passbook_generate` | `site?` `length?` `symbols?` `digits?` `reveal?` | `saved` / `length` / `entropyBits` / `strength` / `masked` /（`reveal` 时）`value` | 有 `site` 则写库 |
| `passbook_set` | `site` + 任意字段 | 写入后的 `fields[]` | 写库（字段级合并） |
| `passbook_get` | `site` `field?` `confirm?` | `value` + `strength`/`entropyBits`（password） | 读库、写轨迹（含 refused） |
| `passbook_use` | `site` `program` `args?` `envName?` `cwd?` `timeoutMs?` | `exitCode` / `stdout` / `stderr`（脱敏）/ `redactionHits` | 起子进程、写轨迹 |
| `passbook_audit` | `deep?` `rotationDays?` | `findings[]` / `reusedGroups` / `total` | 读库（deep 时读值）、写轨迹 |
| `passbook_selftest` | — | `passed`/`total`/`steps[]` | **只在临时库**读写 |

### 4.2 调用点清单（谁在用）

| 调用点 | 用途 | 状态 |
|---|---|---|
| 我（web 会话 · 工具面） | 生成/取用/体检 | **[待线上验收]**（挂载后生效） |
| `scripts/verify-pipeline.mjs` | 端到端验证 vault 接缝（复用 `lib/passbook.js`） | 已实测 13/13 |
| `passbook_selftest` 工具 | 装载后自证（临时库全链路） | **[待线上验收]** |

### 4.3 外部依赖契约（vault.ps1）

- 动作：`init|list|list-json|verify|set|get|remove`；参数 `-Site -User -PasswordStdin -Totp -Recovery -Notes -Field -Force -VaultPath`。
- 退出码：`0` 成功 / `2` 库不存在 / `3` 解密失败 / `4` 解析失败 / `5` 结构版本不符 / `6` 参数或条目问题。
- `set` **字段级合并**（只覆盖给到的字段）；`get -Field fields` 给非密清单；秘密字段需 `-Force`。
- `list-json` 输出**单行 JSON 数组**（`site/username/fields/updatedAt`）。

---

## 5 · 边界与信任

- **信任边界**：本插件信任 `vault.ps1` 的实现（同一机器的同一份脚本）；不信任**输出解析**（`list-json` 可能混入警告文本 ⇒ 宽容解析 + 失败显式报错，I7）。
- **能力 ≠ 沙箱**：同进程 JS 仍可绕过 `ctx` 调 OS。任何「本插件保证秘密不外泄」的说法只在**本插件控制的路径**上成立（stdin 通道、env 注入、脱敏、轨迹无值）。
- **不越界**：不读主人的 `.credentials.yaml`；不把主人的凭据引入我的库（§5.25 I1/G4）。
- **可切断**：库文件可整体轮换/重建（`init -Force`）；插件可卸载而不影响库。

---

## 6 · 与实现的关系

| 契约 | 实现落点 |
|---|---|
| 纯逻辑（生成/强度/掩码/脱敏/指纹/退出码/解析/argv/体检/轨迹） | `src/passbook.ts` |
| 工具注册与副作用编排 | `src/index.ts`（`ctx.tools.register(defineTool(...))`） |
| 端到端接缝验证 | `scripts/verify-pipeline.mjs` |
| 隐私不变量回归 | `tests/passbook.test.mjs`（32 条） |

---

## 7 · 可证伪验收

> 判据列最后一格 = 解析器读取位（行内最后一个非空单元格），状态词只用「已实测 / 待验收 / 待线上验收」。

| # | 验收项 | 判据（可一次测量判真假） | 证据 | 状态 |
|---|---|---|---|---|
| A1 | 生成器真随机且覆盖四类池 | 200 次无重复；每值含大小写/数字/符号 | `pnpm test` → 32/32 | 已实测 ✔ |
| A2 | 默认排除易混字符 | 200 次生成中不出现 `l I O 0 1` | 同上 | 已实测 ✔ |
| A3 | 长度钳制 | `length=3→8`、`9999→256`、`32.9→32` | 同上 | 已实测 ✔ |
| A4 | 强度分档 | `password→weak`、24 字符四类 → `very-strong` | 同上 | 已实测 ✔ |
| A5 | 掩码不漏值 | `maskValue` 输出不含原值任何字符且给出长度 | 同上 | 已实测 ✔ |
| A6 | 脱敏覆盖三形态 | 原文/URL 编码/base64 全部替换，`hits ≥ 3` | 同上 | 已实测 ✔ |
| A7 | 退出码语义不掩盖 | 6 类映射两两不同；未知码归 `unknown` | 同上 | 已实测 ✔ |
| A8 | 解析失败显式报错 | 垃圾输入 → `ok:false` + 明确文案（不给空数组） | 同上 | 已实测 ✔ |
| A9 | 秘密不进 argv | `buildVaultArgs(set,{passwordStdin})` 中无秘密值 | 同上 | 已实测 ✔ |
| A10 | 体检报告不泄漏值 | deep 报告序列化后不含口令，只含指纹 | 同上 | 已实测 ✔ |
| A11 | 轨迹不含值 | `traceLine` 输出无 `value` 键；缺省字段不出现键 | 同上 | 已实测 ✔ |
| A12 | DPAPI 密文往返一致 | 写入 24 字符 → 取回逐字符相等 | `node scripts/verify-pipeline.mjs` → 13/13 | 已实测 ✔ |
| A13 | `-Force` 闸门真会拦 | 无 `-Force` 取秘密 → 退出码 6 且提示 `-Force` | 同上 | 已实测 ✔ |
| A14 | 字段级合并不抹字段 | 二次 `set` 只给 totp 后，password 仍在 | 同上 | 已实测 ✔ |
| A15 | 夹具隔离（不碰真库） | 全链路 `-VaultPath` 指向临时目录；删除干净 | 同上 | 已实测 ✔ |
| A16 | 工具装载后可用（模型可见面） | `passbook_list` 返回真实条目元数据 | 挂载后调用 | 待线上验收 |
| A17 | 装载后自检通过 | `passbook_selftest` → `passed == total` | 挂载后调用 | 待线上验收 |

**统计**：总数 17 · 已实测 15 · 待线上验收 2 ⇒ **不得声明 `verified`**（§5.20：`verified` 要求 pending==0）。

---

## 8 · 实践修订记录

| 日期 | 事件 | 回修 |
|---|---|---|
| 2026-09-17 | 初版（主人指令「创建一个新的插件，叫做隐私密码本插件」） | 首版契约即含 I1–I7 与 A1–A17 |
| 2026-09-17 | 构建期 `noUncheckedIndexedAccess` 报 TS2345 ×2（索引取值 `string \| undefined`） | 字符池取值加非空断言；**不外扩**（断言点仅两处，均为「随机索引必命中」的语义事实） |

---

## 9 · 未决问题

1. **Q1**：`totp`/`recovery` 目前只能走命令行参数（vault.ps1 只对 password 留 stdin）⇒ 拟给 `vault.ps1` 加通用 `-ValueStdin`，让所有秘密字段都有非参数通道。**未做**（属改动身份库脚本，须单独验证）。
2. **Q2**：`passbook_use` 的子进程输出脱敏只覆盖「精确值 / URL 编码 / base64」三形态；十六进制或分片输出仍可能漏 ⇒ 是否加「长度+字符集启发式」误伤风险待定。
3. **Q3**：是否需要 `passbook_rotate`（生成新值 → 写入 → 返回旧值指纹用于核对上游站点）？**待定**。
4. **Q4**：轨迹文件与 memory 的边界——「我取过哪条」是否也该进记忆库？倾向**不进**（轨迹是审计面，记忆是行为面）。
