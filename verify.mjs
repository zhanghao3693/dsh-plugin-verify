/**
 * DSH 插件实装验证（阶段二 · 真装实测）
 *
 * 职责：把插件真正装进一次性 dsh 环境，记录成功/失败与失败原因，
 *       回传给 dpharness.com（站点侧接收端点 POST /api/verify/report）。
 *
 * 与阶段一（静态校验）的区别：
 *   阶段一 = 看元数据（归档/Node 要求），不装
 *   阶段二 = 真的 dsh plugin add 一遍，得出运行时结论
 *
 * 环境变量：
 *   DPH_API_URL   站点地址，默认 https://dpharness.com
 *   DPH_API_TOKEN 回传鉴权（与站点 env 的 VERIFY_TOKEN 一致）
 *   VERIFY_LIMIT  本轮最多验证多少个（默认 100，控制 Actions 时长）
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const exec = promisify(execFile);
const API = process.env.DPH_API_URL || "https://dpharness.com";
const TOKEN = process.env.DPH_API_TOKEN || "";
const LIMIT = parseInt(process.env.VERIFY_LIMIT || "100", 10);
const DSH_TIMEOUT = 180_000; // 单个插件安装超时 3 分钟

/** 失败原因分类：把 stderr 映射到可读结论（对齐 dsh-suite 的 🟢/🔴 徽章语义） */
function classifyError(stderr, stdout) {
  const s = `${stderr}\n${stdout}`.toLowerCase();
  if (!s.trim()) return { ok: false, reason: "unknown", detail: "无输出" };
  if (/404|not found|repository.*not|could not resolve/.test(s) && /repo|github/.test(s))
    return { ok: false, reason: "repo_missing", detail: "仓库不存在或已删除" };
  if (/engines|node version|unsupported node|requires node/.test(s))
    return { ok: false, reason: "node_version", detail: "Node 版本不满足要求" };
  if (/peer|eresolve|conflict|unmet/.test(s))
    return { ok: false, reason: "dependency_conflict", detail: "依赖/peer 冲突" };
  if (/ignored build scripts|allowbuilds|approve-builds/.test(s))
    return { ok: false, reason: "build_script_blocked", detail: "构建脚本被包管理器拦截" };
  if (/network|econnreset|etimedout|enotfound/.test(s))
    return { ok: false, reason: "network", detail: "网络问题（可能是 CI 环境限制）" };
  return { ok: false, reason: "unknown", detail: s.slice(0, 200) };
}

async function run(cmd, args, opts = {}) {
  try {
    const { stdout, stderr } = await exec(cmd, args, { timeout: DSH_TIMEOUT, ...opts });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code ?? 1, stdout: e.stdout || "", stderr: e.stderr || String(e.message) };
  }
}

async function main() {
  console.log("▶ 准备一次性 dsh 环境");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "dsh-verify-"));
  const env = { ...process.env, HOME: home, DSH_CONFIG_DIR: path.join(home, ".dsh") };
  fs.mkdirSync(env.DSH_CONFIG_DIR, { recursive: true });

  const nodeV = (await run("node", ["-v"])).stdout.trim();
  console.log(`  Node ${nodeV}`);

  console.log("▶ 安装 dsh CLI");
  const install = await run("npm", ["i", "-g", "@deepseek-ai/dsh"], { env });
  if (install.code !== 0) {
    console.error("dsh CLI 安装失败：", install.stderr.slice(0, 300));
    process.exit(1);
  }
  console.log("  dsh CLI 就绪");

  console.log("▶ 取待验证插件列表");
  if (!TOKEN) {
    console.error("❌ DPH_API_TOKEN 未配置——回传与取列表都无法鉴权，请检查仓库 Secret");
    process.exit(1);
  }
  let list = [];
  try {
    const res = await fetch(`${API}/api/verify/queue?limit=${LIMIT}`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    const body = await res.text();
    console.log(`  HTTP ${res.status} | 响应前 200 字符: ${body.slice(0, 200)}`);
    if (!res.ok) {
      console.error(`❌ queue 请求失败 HTTP ${res.status}——401/403 = token 不一致，检查 Secret DPH_API_TOKEN 与站点 env VERIFY_TOKEN`);
      process.exit(1);
    }
    list = JSON.parse(body).items || [];
  } catch (e) {
    console.error("❌ 取列表异常：", String(e).slice(0, 300));
    process.exit(1);
  }
  if (!list.length) {
    console.error("❌ 列表为空（站点返回 0 个插件）——异常情况，报错退出");
    process.exit(1);
  }
  console.log(`  本轮验证 ${list.length} 个插件`);

  const results = [];
  for (const fullName of list) {
    const r = await run("dsh", ["plugin", "add", fullName], { env });
    const started = Date.now();
    let item;
    if (r.code === 0) {
      item = { fullName, status: "pass", reason: null, detail: null, durationMs: Date.now() - started };
    } else {
      const c = classifyError(r.stderr, r.stdout);
      item = { fullName, status: "fail", reason: c.reason, detail: c.detail, durationMs: Date.now() - started };
    }
    console.log(`  ${item.status === "pass" ? "🟢" : "🔴"} ${fullName} ${item.reason ? "(" + item.reason + ")" : ""}`);
    results.push(item);
    // 每个插件独立配置目录，避免互相污染
    fs.rmSync(env.DSH_CONFIG_DIR, { recursive: true, force: true });
    fs.mkdirSync(env.DSH_CONFIG_DIR, { recursive: true });
  }

  const outFile = "verify-results.json";
  fs.writeFileSync(outFile, JSON.stringify({ ranAt: new Date().toISOString(), node: nodeV, results }, null, 1));
  console.log(`\n结果写入 ${outFile}（成功 ${results.filter((r) => r.status === "pass").length}/${results.length}）`);

  if (TOKEN) {
    console.log("▶ 回传站点");
    try {
      const res = await fetch(`${API}/api/verify/report`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
        body: fs.readFileSync(outFile, "utf8"),
      });
      console.log("  回传状态：", res.status, (await res.text()).slice(0, 120));
    } catch (e) {
      console.error("  ❌ 回传失败：", String(e).slice(0, 300));
      process.exitCode = 1;
    }
  } else {
    console.log("（未配置 DPH_API_TOKEN，跳过回传）");
  }
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
