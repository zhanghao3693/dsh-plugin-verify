# dsh-plugin-verify

DSH 插件**实装验证**流水线（dpharness.com 阶段二）。每天把插件真的装进一次性 dsh 环境，记录结论与原因，回传站点展示徽章。

公开仓库，Actions 免费无限额度。

## 文件

| 文件 | 作用 |
|---|---|
| `verify.mjs` | 验证脚本：装 dsh CLI → 按站点给的 `installTarget` 安装 → 分类原因 → 分批回传 |
| `.github/workflows/verify.yml` | 每天 03:00 UTC 定时跑 + 手动触发 |

## 核心约定：验证对象必须 = 推荐对象

站点向用户推荐哪条安装命令，这里就验证哪条 —— 否则结论对用户没有意义。

站点队列接口返回 `targets[]`：

```json
{ "fullName": "dsh-market/dsh-market", "installTarget": "dshmarket", "installKind": "npm" }
```

- `installKind: "npm"` —— 该仓库发布过 npm 包（包内已是预编译产物），走包名安装；
- `installKind: "github"` —— 未确认 npm 包名，回退 `owner/repo`（GitHub 源）安装。

**为什么必须这样**（2026-09-15 修）：此前一律用 `owner/repo` 安装，会触发仓库
`package.json` 的 `prepare` 构建脚本，被 pnpm 的构建脚本白名单拦下，
于是被判 `build_script_blocked / fail`。但站点给用户的命令是 npm 包，
根本不需要构建 —— 两者不是同一条命令。此类误判一度占 `fail` 总数的
**76%（104/136）**，连官方 `deepseek-ai/deepseek-harness`（22.4 万★）都被标成「未通过」。

## 结论三态

| status | 含义 | 站点落库 |
|---|---|---|
| `pass` | 真的装成功 | `verifyStatus = pass` |
| `fail` | 确实装不上（插件侧问题） | `verifyStatus = fail` |
| `skip` | **无法判定**（验证环境侧原因，不构成对插件的结论） | `verifyStatus = none` |

`skip` 的意义：宁可不给结论，也不给错结论。

## 失败原因分类

| reason | 含义 | 归类 |
|---|---|---|
| `repo_missing` | 仓库不存在/已删除 | → `fail` |
| `node_version` | Node 版本不满足（dsh 要求 ≥ 22.19） | → `fail` |
| `dependency_conflict` | peer / 依赖冲突 | → `fail` |
| `unknown` | 其他（附原始输出） | → `fail` |
| `build_script_blocked` | 构建脚本被包管理器拦截（pnpm allowBuilds） | → `skip`（环境侧） |
| `network` | 网络问题（CI 环境限制） | → `skip`（环境侧） |

## 健壮性设计

1. **增量回传**：每 `VERIFY_BATCH`（默认 10）个回传一次，一轮崩掉不至于结果全丢；
2. **崩溃抢救**：`uncaughtException` / `unhandledRejection` 触发时，把已完成结论尽力回传；
3. **磁盘余量保护**：余量低于 `VERIFY_DISK_MIN_MB` 时**主动优雅收尾并回传**，不等环境杀进程；
4. **资源诊断**：每 `VERIFY_BATCH` 个打印 RSS / heap / 磁盘余量，异常时也打印快照。

### 排查记录：exit 143

2026-09-10 ~ 09-14 连续 5 天 `Run verification` 失败、`report` 零回传，站上 300 条结论全部冻结在 9/9。

从 Actions 日志确认的直接死因：

```
[93/100 410s] ...
Error: Process completed with exit code 143.
```

- `143` = `128 + 15` = **SIGTERM**，即进程被外部终止；
- 发生在 **6m50s / 第 93 个插件**处，而 `timeout-minutes` 是 **180 分钟** —— 不是超时；
- 前后无 `Killed`、无 ENOSPC 报错，因此**高度疑似资源耗尽**（每轮 clone + install 上百个插件，
  依赖在 pnpm store 累积），需靠上面的诊断输出确诊。

无论根因为何，"结果全丢"这一点已由增量回传兜住。

## 需要的 Secret

仓库 Settings → Secrets and variables → Actions：

- `DPH_API_TOKEN` —— 回传鉴权，需与站点 `.env` 的 `VERIFY_TOKEN` 一致

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `DPH_API_URL` | `https://dpharness.com` | 站点地址 |
| `DPH_API_TOKEN` | — | 回传鉴权 |
| `VERIFY_LIMIT` | `100` | 本轮最多验证多少个 |
| `VERIFY_BATCH` | `10` | 每验证多少个回传一次 |
| `VERIFY_DISK_MIN_MB` | `2048` | 磁盘余量低于此值就提前收尾回传（设 0 关闭） |

## 站点侧配套（已上线）

- `GET /api/verify/queue?limit=N` —— 返回 `items[]`（fullName 列表，兼容旧版）与 `targets[]`（含 installTarget）
- `POST /api/verify/report` —— 接收结果写入 Plugin 表（Bearer 鉴权），支持 `status: "skip"`
- 插件页展示：🟢 通过 / ⚪ 环境未跑通 / 一行小字提示未通过

## 本地试跑

```bash
DPH_API_TOKEN=xxx VERIFY_LIMIT=5 node verify.mjs
```
