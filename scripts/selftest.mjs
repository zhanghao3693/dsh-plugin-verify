/**
 * 扫描器自检 —— 每轮扫描前先跑，把「关键不变式」变成自动护栏。
 *
 * 为什么必须每轮跑而不是「改完跑一次」：
 * 下面这几条都是**曾经真实失效过**的机制，而它们的失效方式都是**静默**的 ——
 * 扫描照常出结论、日志照常打印，只是结论变松了（把有命令执行的插件说成安全）。
 * 没有自动断言，这种回归只能靠人偶然发现。
 *
 * 覆盖的四条不变式：
 *   1. 动态拼接命令执行可达（否则高危档整体失效）
 *   2. 剪贴板读/写分开（写剪贴板不该升档）
 *   3. 证据截断不影响判定（CAP 不得污染 decide 的输入）
 *   4. 证据快照取自原文视图（否则展示给用户的证据是一串空格）
 *
 * 用法：node scripts/selftest.mjs [risk-scan.mjs 路径]
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const SCANNER = process.argv[2] || path.join(ROOT, "risk-scan.mjs");
const FIXTURES = path.join(ROOT, "fixtures");

if (!fs.existsSync(SCANNER)) {
  console.error(`✗ 找不到扫描器：${SCANNER}`);
  process.exit(1);
}

const fails = [];
function ok(cond, msg) {
  console.log(`${cond ? "✅" : "❌"} ${msg}`);
  if (!cond) fails.push(msg);
}

/** 跑一次自检模式，返回解析后的 JSON */
async function runSelfTest(fixture) {
  const file = path.join(FIXTURES, fixture);
  const { stdout } = await exec(process.execPath, [SCANNER], {
    env: { ...process.env, SELF_TEST: file },
    maxBuffer: 16 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}

console.log(`▶ 自检目标：${SCANNER}\n`);

// ── 不变式 1：命令首参形态 ────────────────────────────────────────────────
{
  const r = await runSelfTest("fixture-args.mjs");
  const at = (line) => (r.findings || []).find((f) => f.line === line);
  console.log("── 1. 命令首参形态 ──");
  ok(at(6)?.argSource === "static", "L6 exec(\"git status\") → static");
  ok(at(7)?.argSource === "static", "L7 无插值模板串 → static");
  // 这两条是「高危档是否还活着」的直接证据：一旦 maskStrings 之后才判参数形态，
  // 模板串内容已被掩成空格，dynamic_literal 分支在代码上不可达，会退化成 static。
  ok(at(8)?.argSource === "dynamic_literal", "L8 exec(`bash -c ${cmd}`) → dynamic_literal（高危档可达）");
  ok(at(11)?.argSource === "dynamic_literal", "L11 execSync(`rm -rf ${cmd}`) → dynamic_literal（高危档可达）");
  ok(at(9)?.argSource === "config_or_var", "L9 exec(cmd) → config_or_var");
}

// ── 不变式 2：剪贴板读写分离 ──────────────────────────────────────────────
{
  console.log("\n── 2. 剪贴板读写分离 ──");
  const w = await runSelfTest("fixture-clip.mjs");
  const rd = await runSelfTest("fixture-clip2.mjs");
  const wRules = new Set((w.findings || []).map((f) => f.rule));
  const rRules = new Set((rd.findings || []).map((f) => f.rule));
  ok(wRules.has("clipboard_write") && !wRules.has("clipboard_read"), "只写剪贴板 → 记 clipboard_write，不记 read");
  ok(rRules.has("clipboard_read") && !rRules.has("clipboard_write"), "只读剪贴板 → 记 clipboard_read，不记 write");
}

// ── 不变式 3：CAP 截断不得污染判定 ────────────────────────────────────────
{
  console.log("\n── 3. 证据截断不得影响判定 ──");
  const r = await runSelfTest("fixture-cap.mjs");
  ok(r.stats?.command_exec === 8, `全量计数不受截断影响：command_exec = 8（实际 ${r.stats?.command_exec}）`);
  ok((r.execArgs || []).includes("dynamic_literal"), "全量聚合里保留了 dynamic_literal 形态");
  // 核心断言：修正后 high / 修正前 medium。两者相同即说明判定又变回读截断样本了。
  ok(r.level_aggregate === "high", `判定读全量聚合 → high（实际 ${r.level_aggregate}）`);
  ok(r.level_findingsOnly === "medium", `判定读截断样本 → medium（实际 ${r.level_findingsOnly}）—— 与上一条必须不同`);
  ok(r.level_aggregate !== r.level_findingsOnly, "两种判定输入给出不同结论 ⇒ 说明聚合确实在起作用");
}

// ── 不变式 4：证据快照取自原文视图 ────────────────────────────────────────
{
  console.log("\n── 4. 证据快照可读性 ──");
  const r = await runSelfTest("fixture-args.mjs");
  const f10 = (r.findings || []).find((x) => x.line === 10);
  // 掩码视图下这条会变成 spawn("   ", ["      "]) —— 关键证据（真正执行的程序名）是空白，
  // 对一个以「可复现证据」为卖点的功能，证据不可读等于没有证据。
  ok(!!f10?.snippet?.includes("git"), `L10 证据片段保留了真实参数（实际 "${f10?.snippet ?? ""}"）`);
}

console.log("");
if (fails.length) {
  console.error(`❌ 自检失败 ${fails.length} 项 —— 扫描结论不可信，请勿回传站点：`);
  for (const f of fails) console.error(`   · ${f}`);
  process.exit(1);
}
console.log("✅ 自检全部通过");
