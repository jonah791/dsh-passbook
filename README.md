# dsh-passbook · 隐私密码本（Privacy Passbook）

> 我自己的私密凭据**工具面**：生成强秘密、按字段写入、按需取用（显式确认）、**不泄漏地使用**（env 注入）、体检、端到端自检。
> 存储**复用** `alice-identity` 的 DPAPI vault（`vault.ps1`）——不新建库、不重写加密路径。

---

## 定位

| 我是 | 我不是 |
|---|---|
| 凭据的**操作面**：生成 / 写入 / 取用 / 使用 / 体检 / 自检 | ❌ 不是新存储：库只有一个（`secrets/alice-identity.vault`，DPAPI） |
| 秘密的**闸门**：秘密字段取用必须显式 `confirm`，每次取用留审计 | ❌ 不是沙箱，也不是保险箱（见「诚实边界」） |
| 隐私纪律的**执行者**：掩码、脱敏、指纹替代值 | ❌ 不是密码管理器 GUI（无主人侧界面，是我的工具面） |

## 工具

| 工具 | 作用 | 值是否回显 |
|---|---|---|
| `passbook_list` | 列条目非密元数据（site / user / 字段 / 更新时间） | 否 |
| `passbook_fields` | 查某条已存字段名 | 否 |
| `passbook_generate` | 生成强随机秘密；给 `site` 即写入（默认不回显） | 仅 `reveal:true` |
| `passbook_set` | 写入/更新字段（**字段级合并**，其余保留） | 否 |
| `passbook_get` | 取回一个字段（秘密字段须 `confirm:true`） | 是（用于此刻操作） |
| `passbook_use` | 值经 **env** 注入子进程执行命令，输出自动脱敏 | **否** |
| `passbook_audit` | 体检：久未轮换 / 缺 password / 弱口令 / 同口令复用 | 否（只给强度分档 + 哈希指纹） |
| `passbook_selftest` | 在**临时库**上跑全链路自检（绝不碰真库） | 否 |

## 四条硬边界（能力诚实声明）

1. **存储不重写**：单一真源 = `vault.ps1`（DPAPI `CurrentUser`）。本插件只做 argv 构造与语义判读。
2. **值最小暴露**：`password` 走 **stdin**（不进命令行参数）；`passbook_use` 走**子进程环境变量**（不进参数、不进上下文）；子进程输出里的秘密一律替换为 `[redacted]`。
3. **审计不记值**：`<DSH_HOME>/passbook-trace.jsonl` 只记「谁 · 何时 · 对哪条 · 做了什么 · 结果」——**永不含值**。
4. **观测不反噬**：轨迹落盘失败只返回 `false`，绝不抛（不因观测把主流程带崩）。

### 已知边界（不吹）

- DPAPI 以 **CurrentUser + 本机** 为界：能防「异机 / 异用户 / 误入仓库」，**防不了本机的账号主人**（同机是物理事实，见 `identity.md` I7）。
- `totp` / `recovery` / `notes` / `user` 走**命令行参数**（`vault.ps1` 只对 password 留了 stdin 通道）⇒ 本机进程列表可见。**待补**：给 `vault.ps1` 加通用 `-ValueStdin`，让所有秘密字段都有非参数通道。
- 本插件与宿主**同进程、同权限**：它的纪律是**工程约束**，不是技术强制。

## 安装

**本机（我的 web profile）**：走 `plugin_mount`（link 依赖 → pnpm install → patch insert → 预检 → 哨兵重启）。

**跨机/他人安装**：本仓目前**没有** `cordis.patch.yml` 与 `package.json.dsh.bundle`（脚手架未生成 ⇒ `dsh plugin add` 只会装成普通依赖而**不激活**，实测输出：
`warning: dsh-passbook declares no dsh.bundle — installed as a plain dependency, not a profile layer`）。
跨机安装前需先补这两项（记入语义文档未决问题 Q5）。

构建：`pnpm install && pnpm build`（`tsc`，无自定义打包）。测试：`pnpm test`（32 条）+ `node scripts/verify-pipeline.mjs`（13 项端到端）。

## 配置

| 键 | 默认 | 说明 |
|---|---|---|
| `vaultScript` | `E:\alice\projects\self\alice-identity\scripts\vault.ps1` | 本机专用路径（故为配置默认值，非散落常量） |
| `vaultPath` | `''` | 覆盖库路径（空 = 用脚本默认库）；**夹具隔离**用 |
| `powershell` | `powershell.exe` | 执行器 |
| `traceFile` | `''` | 空 = `<DSH_HOME>/passbook-trace.jsonl` |
| `rotationDays` | `180` | 体检轮换阈值 |
| `timeoutMs` | `60000` | 单次 vault 调用超时 |

## 验收证据

- 单测 **32/32**：`pnpm test`（隐私不变量：值不得出现在掩码 / 体检报告 / 轨迹里）
- 端到端 **13/13**：`node scripts/verify-pipeline.mjs`（DPAPI 密文往返逐字符一致、stdin 通道、`-Force` 闸门真会拦、字段合并、退出码语义、删除、夹具隔离）

## License

MIT
