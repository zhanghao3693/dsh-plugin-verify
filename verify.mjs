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
 * ── 2026-09-15 修口径误判（起因：dsh-market 作者来信）────────────────────────
 * 症状：插件详情页挂着「实装验证未通过（build_script_blocked）」，
 *       而作者确认官方安装方式在正常环境下可以正常安装。
 *
 * 根因：验证的**命令**和站点推荐给用户的**不是同一条**——
 *   · 本脚本原先一律用 `owner/repo`（GitHub 源）安装；
 *   · GitHub 源安装会触发仓库 package.json 的 `prepare` 构建脚本；
 *   · pnpm（v10 起）默认不允许依赖执行构建脚本，于是拦下并打印
 *     "Ignored build scripts"，脚本被判为 build_script_blocked / fail；
 *   · 但站点给用户的命令是 npm 包（如 `dshmarket`），包内已是预编译产物
 *     （实测 dshmarket@1.46.1：154 文件、解包 3.1MB，lib/ 已编译），无需构建。
 *
 * 影响面：此类误判占当时 fail 总数的 76%（104/136），连官方仓库
 *         deepseek-ai/deepseek-harness（22.4 万★）都被标成「未通过」。
 *
 * 修正：
 *   1. 安装目标改用站点队列返回的 installTarget（有 npm 包名就用包名）；
 *   2. 环境侧原因（构建脚本拦截 / 网络）上报 status:"skip" ——
 *      站点落库为 none，宁可不给结论也不给错结论；
 *   3. 每 BATCH 个增量回传一次 + 崩溃前抢救回传，避免一轮崩掉结果全丢
 *      （2026-09-10 起连续 5 天 Run verification 失败、report 零回传的教训）。
 *
 * 环境变量：
 *   DPH_API_URL   站点地址，默认 https://dpharness.com
 *   DPH_API_TOKEN 回传鉴权（与站点 env 的 VERIFY_TOKEN 一致）
 *   VERIFY_LIMIT  本轮最多验证多少个（默认 100，控制 Actions 时长）
 *   VERIFY_BATCH  每验证多少个回传一次（默认 10）
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
const BATCH = Math.max(1, parseInt(process.env.VERIFY_BATCH || "10", 10));
// 磁盘余量保护阈值（MB）：低于它就提前收尾并回传，别等环境把进程杀掉。
// 每次 dsh plugin add 都会往 pnpm store 落依赖，100 个插件累积可观。
const DISK_MIN_MB = Math.max(0, parseInt(process.env.VERIFY_DISK_MIN_MB || "2048", 10));
const DSH_TIMEOUT = 180_000; // 单个插件安装超时 3 分钟
const MAX_BUFFER = 10 * 1024 * 1024; // dsh/pnpm 输出可能很大，默认 1MB 会截断

const OUT_FILE = "verify-results.json";

/**
 * 「环境侧」失败原因：与插件本身能不能装无关，只反映验证环境的策略差异。
 * 这类原因上报 skip（站点落 none），不计入 fail。
 * 与站点侧保持一致：app/api/verify/report/route.ts、详情页的 ENV_SIDE_REASONS。
 */
const ENV_SIDE_REASONS = new Set(["build_script_blocked", "network"]);

/** 失败原因分类：把 stderr 映射到可读结论（对齐 dsh-suite 的 🟢/🔴 徽章语义） */
function classifyError(stderr, stdout) {
  const s = `${stderr}\n${stdout}`.toLowerCase();
  if (!s.trim()) return { reason: "unknown", detail: "无输出" };
  if (/404|not found|repository.*not|could not resolve/.test(s) && /repo|github/.test(s))
    return { reason: "repo_missing", detail: "仓库不存在或已删除" };
  if (/engines|node version|unsupported node|requires node/.test(s))
    return { reason: "node_version", detail: "Node 版本不满足要求" };
  if (/peer|eresolve|conflict|unmet/.test(s))
    return { reason: "dependency_conflict", detail: "依赖/peer 冲突" };
  if (/ignored build scripts|allowbuilds|approve-builds/.test(s))
    return {
      reason: "build_script_blocked",
      detail: "构建脚本被包管理器拦截（GitHub 源会触发 prepare 构建；改走 npm 包则无需构建）",
    };
  if (/network|econnreset|etimedout|enotfound/.test(s))
    return { reason: "network", detail: "网络问题（可能是 CI 环境限制）" };
  return { reason: "unknown", detail: s.slice(0, 200) };
}

async function run(cmd, args, opts = {}) {
  try {
    const { stdout, stderr } = await exec(cmd, args, {
      timeout: DSH_TIMEOUT,
      maxBuffer: MAX_BUFFER,
      ...opts,
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return {
      code: e.code ?? 1,
      stdout: e.stdout || "",
      stderr: e.stderr || String(e.message || e),
    };
  }
}

const results = [];
const pending = [];
/** 非 null 表示本轮提前收尾（如磁盘余量触发阈值），用于收尾时说明原因 */
let earlyStop = null;

/** 回传（增量或收尾）。失败不抛出——回传失败不该让整轮结果作废。 */
async function report(items, label = "回传") {
  if (!TOKEN || !items.length) return false;
  try {
    const res = await fetch(`${API}/api/verify/report`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({ ranAt: new Date().toISOString(), results: items }),
    });
    const text = await res.text();
    console.log(`  ${label} ${items.length} 条 → HTTP ${res.status} ${text.slice(0, 120)}`);
    return res.ok;
  } catch (e) {
    console.error(`  ✗ ${label}失败：${String(e).slice(0, 200)}`);
    return false;
  }
}

function saveResults() {
  try {
    fs.writeFileSync(
      OUT_FILE,
      JSON.stringify({ ranAt: new Date().toISOString(), node: process.version, results }, null, 1)
    );
    console.log(`  结果写入 ${OUT_FILE}（成功 ${results.filter((r) => r.status === "pass").length}/${results.length}）`);
  } catch (e) {
    console.error(`  ✗ 写 ${OUT_FILE} 失败：${String(e).slice(0, 200)}`);
  }
}

/** 磁盘余量诊断：整轮要 clone/install 上百个插件，Actions 盘小易爆 */
function diskFreeMB(p) {
  try {
    const s = fs.statfsSync(p);
    return Math.round((s.bavail * s.bsize) / 1024 / 1024);
  } catch {
    return null;
  }
}

let fatalHandled = false;
/** 崩溃抢救：把已完成的结论回传出去，别让一整轮白跑（9/10~9/14 的教训） */
async function fatal(where, err) {
  if (fatalHandled) return;
  fatalHandled = true;
  console.error(`\n✗ 崩溃于 ${where}：${err?.stack ? err.stack.slice(0, 1000) : String(err).slice(0, 1000)}`);
  console.error(`  已完成 ${results.length} 个，待回传 ${pending.length} 个 —— 尽力抢救回传`);
  const mu = process.memoryUsage();
  console.error(
    `  资源快照：rss=${Math.round(mu.rss / 1048576)}MB heap=${Math.round(mu.heapUsed / 1048576)}MB` +
      ` diskRoot=${diskFreeMB("/")}MB diskTmp=${diskFreeMB(os.tmpdir())}MB diskHome=${diskFreeMB(HOME_DIR)}MB`
  );
  try {
    if (pending.length) await report(pending.splice(0), "[抢救]");
    if (results.length) {
      saveResults();
      await report(results, "[全量补发]");
    }
  } catch {}
  process.exit(1);
}

const HOME_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "dsh-verify-"));
process.on("uncaughtException", (e) => void fatal("uncaughtException", e));
process.on("unhandledRejection", (e) => void fatal("unhandledRejection", e));

async function main() {
  console.log("▶ 准备一次性 dsh 环境");
  const env = { ...process.env, HOME: HOME_DIR, DSH_CONFIG_DIR: path.join(HOME_DIR, ".dsh") };
  fs.mkdirSync(env.DSH_CONFIG_DIR, { recursive: true });

  const nodeV = (await run("node", ["-v"])).stdout.trim();
  console.log(`  Node ${nodeV}｜磁盘余量 tmp=${diskFreeMB(os.tmpdir())}MB`);

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
  let targets = [];
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
    const parsed = JSON.parse(body);
    list = parsed.items || [];
    // targets 是站点侧新增的「实际推荐安装目标」；旧版站点没有该字段时回退成 fullName，
    // 保持向后兼容（届时口径仍会走 GitHub 源，属于已知降级）。
    targets = Array.isArray(parsed.targets) && parsed.targets.length
      ? parsed.targets
      : list.map((f) => ({ fullName: f, installTarget: f, installKind: "github" }));
  } catch (e) {
    console.error("❌ 取列表异常：", String(e).slice(0, 300));
    process.exit(1);
  }
  if (!list.length) {
    console.error("❌ 列表为空（站点返回 0 个插件）——异常情况，报错退出");
    process.exit(1);
  }
  const npmCount = targets.filter((t) => t.installKind === "npm").length;
  console.log(`  本轮验证 ${targets.length} 个插件（npm 包路径 ${npmCount} / GitHub 源 ${targets.length - npmCount}）`);

  // dsh 的 plugin 子命令运行在 profile 上下文（内部是 pnpm 转发器），
  // 缺 --profile 必报 "required option '--profile <name>'"（2026-09-08 第一轮 100/100 失败的根因）。
  // profile 首次使用自动初始化，无需预创建。
  console.log("▶ 初始化 verify profile");
  await run("dsh", ["plugin", "--profile", "verify", "list"], { env });

  const t0 = Date.now();
  for (let i = 0; i < targets.length; i++) {
    // 磁盘余量保护：低于阈值就优雅收尾并回传，别等 runner 把进程杀掉。
    // 9/14 那次以 exit 143（SIGTERM）在第 93 个插件处终止，已完成部分全部作废。
    const freeBefore = diskFreeMB("/");
    if (freeBefore !== null && DISK_MIN_MB > 0 && freeBefore < DISK_MIN_MB) {
      console.log(`⚠ 磁盘余量 ${freeBefore}MB 低于阈值 ${DISK_MIN_MB}MB，提前收尾并回传已完成部分`);
      earlyStop = `磁盘余量 ${freeBefore}MB 触发阈值`;
      break;
    }

    const { fullName, installTarget = fullName, installKind = "github" } = targets[i];
    const started = Date.now();
    const r = await run("dsh", ["plugin", "--profile", "verify", "add", installTarget], { env });

    let item;
    if (r.code === 0) {
      item = { fullName, installTarget, status: "pass", reason: null, detail: null, durationMs: Date.now() - started };
    } else {
      const c = classifyError(r.stderr, r.stdout);
      let detail = c.detail;
      if (c.reason === "unknown" && !results.some((x) => x.reason === "unknown")) {
        // 第一个 unknown 附带 dsh plugin --help，帮助定位命令格式
        const help = await run("dsh", ["plugin", "--profile", "verify", "--help"], { env });
        detail = (c.detail + " || HELP: " + (help.stdout || help.stderr).slice(0, 400)).slice(0, 500);
      }
      // 环境侧原因 → skip（站点落 none，不计入 fail）
      const status = ENV_SIDE_REASONS.has(c.reason) ? "skip" : "fail";
      item = { fullName, installTarget, status, reason: c.reason, detail, durationMs: Date.now() - started };
    }

    const icon = item.status === "pass" ? "🟢" : item.status === "skip" ? "⚪" : "🔴";
    const elapsed = ((Date.now() - t0) / 1000).toFixed(0);
    console.log(`  [${i + 1}/${targets.length} ${elapsed}s] ${icon} ${fullName}${item.reason ? " (" + item.reason + ")" : ""}${installKind === "npm" ? " [npm]" : ""}`);
    results.push(item);
    pending.push(item);

    // 增量回传：一轮崩掉不至于结果全丢（9/10~9/14 连续 5 天 report 零回传的教训）
    if (pending.length >= BATCH) await report(pending.splice(0));

    // 资源诊断：9/14 那次以 exit 143（SIGTERM）在第 93 个插件处被杀，
    // 不是 job 超时（timeout-minutes 是 180 分钟），高度疑似内存或磁盘耗尽。
    // 每处理一个就记一行，下次运行即可确定是哪个资源在往下掉。
    if ((i + 1) % BATCH === 0) {
      const mu = process.memoryUsage();
      console.log(
        `  [诊断 ${i + 1}] rss=${Math.round(mu.rss / 1048576)}MB heap=${Math.round(mu.heapUsed / 1048576)}MB` +
          ` diskRoot=${diskFreeMB("/")}MB diskTmp=${diskFreeMB(os.tmpdir())}MB`
      );
    }

    // 每个插件独立配置目录，避免互相污染
    fs.rmSync(env.DSH_CONFIG_DIR, { recursive: true, force: true });
    fs.mkdirSync(env.DSH_CONFIG_DIR, { recursive: true });
  }

  if (pending.length) await report(pending.splice(0));
  saveResults();

  const pass = results.filter((r) => r.status === "pass").length;
  const skip = results.filter((r) => r.status === "skip").length;
  const fail = results.filter((r) => r.status === "fail").length;
  console.log(`\n完成：🟢 通过 ${pass}｜⚪ 无法判定 ${skip}｜🔴 未通过 ${fail}（共 ${results.length}）`);
  if (earlyStop) console.log(`⚠ 本轮提前收尾：${earlyStop}——已完成部分已回传，剩余顺延下一轮`);
  console.log(`磁盘余量：root=${diskFreeMB("/")}MB tmp=${diskFreeMB(os.tmpdir())}MB`);

  // 收尾不再重复全量回传（上面已分批回传过）；失败才补
  if (!TOKEN) console.log("（未配置 DPH_API_TOKEN，跳过回传）");
}

main().catch((e) => fatal("main", e));
