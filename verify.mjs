name: dsh plugin verify

# DSH 插件实装验证（阶段二）：每天跑一遍，把插件真的装进一次性 dsh 环境，
# 结果回传 dpharness.com，插件页展示 🟢/🔴 徽章 + 失败原因。
#
# 公开仓库 Actions 免费无限额度——这是零成本对齐 dsh-suite CI 能力的关键。

on:
  schedule:
    # 每天 03:00 UTC（北京时间 11:00）
    - cron: "0 3 * * *"
  workflow_dispatch:
    inputs:
      limit:
        description: "本轮验证插件数"
        required: false
        default: "100"

jobs:
  verify:
    runs-on: ubuntu-latest
    timeout-minutes: 180
    steps:
      - uses: actions/checkout@v4

      # dsh 要求 Node ≥ 22.19
      - uses: actions/setup-node@v4
        with:
          node-version: "22.19"

      # dsh 的插件管理是 pnpm 转发器（pnpm not found = 全军覆没，09-08 第三轮教训）
      - name: Enable pnpm
        run: corepack enable

      - name: Run verification
        env:
          DPH_API_URL: https://dpharness.com
          DPH_API_TOKEN: ${{ secrets.DPH_API_TOKEN }}
          VERIFY_LIMIT: ${{ github.event.inputs.limit || '100' }}
        run: node verify.mjs

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: verify-results
          path: verify-results.json
          retention-days: 30
