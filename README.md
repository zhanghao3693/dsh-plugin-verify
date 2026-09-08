# dsh-plugin-verify

DSH 插件**实装验证**流水线（dpharness.com 阶段二）。每天把插件真的装进一次性 dsh 环境，记录成功/失败与失败原因，回传站点展示 🟢/🔴 徽章。

公开仓库，Actions 免费无限额度。

## 文件

| 文件 | 作用 |
|---|---|
| `verify.mjs` | 验证脚本：装 dsh CLI → `dsh plugin add owner/repo` → 分类失败原因 → 回传 |
| `.github/workflows/verify.yml` | 每天 03:00 UTC 定时跑 + 手动触发 |

## 失败原因分类

| reason | 含义 |
|---|---|
| `repo_missing` | 仓库不存在/已删除 |
| `node_version` | Node 版本不满足（dsh 要求 ≥ 22.19） |
| `dependency_conflict` | peer / 依赖冲突 |
| `build_script_blocked` | 构建脚本被包管理器拦截（pnpm allowBuilds） |
| `network` | 网络问题（CI 环境限制） |
| `unknown` | 其他（附原始输出） |

## 需要的 Secret

仓库 Settings → Secrets and variables → Actions：

- `DPH_API_TOKEN` —— 回传鉴权，需与站点 `.env` 的 `VERIFY_TOKEN` 一致

## 站点侧配套（待开发）

- `GET /api/verify/queue?limit=N` —— 返回待验证插件 fullName 列表（按 star/安装量排序）
- `POST /api/verify/report` —— 接收结果写入 Plugin 表（Bearer 鉴权）
- 插件页展示：🟢/🔴 徽章 + 原因 + 验证时间

## 本地试跑

```bash
npm i
DPH_API_TOKEN=xxx node verify.mjs
```
