/**
 * DSH 插件静态风险扫描器 v2.7.0
 *
 * 职责：静态分析插件源码，输出**可复现的能力事实 + 证据**（规则/文件/行号/代码片段，
 *       命令执行另记首参形态），回传给 dpharness.com（POST /api/risk/report）。
 *
 * 与 verify.mjs 的分工：
 *   verify.mjs = 「装得上吗」—— 真的 dsh plugin add 一遍
 *   本脚本      = 「装上了它会做什么」—— 读源码，不执行任何插件代码
 * 两者证据基础不同，各自独立落库（verifyStatus* 与 riskAuto* 两组字段），互不覆盖。
 *
 * ── 两种运行方式 ─────────────────────────────────────────────────────────
 *   CI 模式（RISK_CI=1）：从 /api/risk/queue 取目标 → 扫描 → 分批回传
 *   本地模式：node risk-scan.mjs <targets.json> <out.jsonl>（断点续扫）
 * 两种方式共用同一个 scanOne()，保证「本地验证过的结论」对 CI 同样成立。
 *
 * ── 设计原则（改代码前必读，每条都是实测换来的）──────────────────────────
 *
 * 1. **输出能力事实，不输出等级结论。** 等级映射归口径层（decide()），
 *    因为「什么算高危」是产品决策，不是技术事实 —— 它必须显式、可审计、可改，
 *    改口径不该要求重新扫一遍全站。同一批事实可投出多套分布做对比。
 *
 * 2. **漏报 > 误报。** 漏报给出的是用户会相信的错误结论（把能执行命令的插件
 *    说成安全）；误报只是噪音。冲突时永远偏向不漏。
 *    ⇒ 绝不用「少扫文件 / 少记事实」压误报，那是把误报换成漏报。
 *
 * 3. **无法判定必须显式化。** 取不到源码 → no_source，绝不默认落 low。
 *    绝不出现「我们扫不到所以判定它安全」。
 *
 * 4. **存多少条证据 ≠ 判定用什么事实。** 证据按规则截断（CAP）只为控制入库体积，
 *    判定读的是不受截断影响的全量聚合（stats / execArgs / hosts）。
 *    实测踩过：CAP 一度被当成判定输入，同文件第 7 条之后的「动态拼接命令执行」
 *    （高危信号）静默消失，等级被判低。
 *
 * 5. **三视图分离**：code（字符串掩码，供标识符匹配）/ specifiers（保留 import
 *    模块名与字面量）/ strings（字面量表）。只用掩码视图会丢掉
 *    `import { spawn } from "node:child_process"` 的模块名（漏报）；
 *    只用原文视图会把语言包里的界面文案当代码（误报）。
 *
 * 6. **实参形态与证据快照用 rawLines**（= specifiers 按行切分，保留字符串内容）。
 *    跑在掩码视图上会让 dynamic_literal 分支**代码上不可达**，高危档彻底失效。
 *
 * 7. **源码范围 = 入口闭包 ∪ fallback 并集，npm 源也要并集**（闭包非空不代表完整）；
 *    `bin` 不能当开发目录跳过；`scripts/` 不能按目录名一刀切（看 files 字段）。
 *
 * 8. **不设 devOnly 机制**：`"check": "node --check a.mjs && ..."` 这类自检脚本
 *    会引用包内全部真实运行时代码，据此把文件标成开发脚本会造成 false low。
 *
 * ── 自检 ────────────────────────────────────────────────────────────────
 *   SELF_TEST=<fixture.mjs> node risk-scan.mjs
 * 三组夹具（命令首参形态 / 剪贴板读写分离 / CAP 不污染判定）见仓库 README。
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const RULE_VERSION = "v2.7.0";

/* ────────────────────── 1. 注释剥离 + 字符串掩码 ────────────────────── */

/**
 * 一次遍历产出三个视图：
 *   code      —— 注释删除、字符串内容替换为等长空格（行号完全保留）→ 供标识符/API 匹配
 *   specifiers—— 同 code，但**字符串字面量原样保留** → 仅供 import/require 解析
 *   strings   —— 全部字符串字面量 {value, line, quote}
 *
 * 为什么必须分离出 specifiers（v2.1 首跑踩的坑）：
 *   掩码把 `import { spawn } from "node:child_process"` 的模块名一起抹成了空格，
 *   于是 parseBindings 拿到空模块名 → child_process / fs 绑定全为空 →
 *   **better-sidebar 明明有 6 处 spawn、被扫成「低风险且无命令执行」**。
 *   绑定解析需要模块名，标识符匹配不能让字符串污染 —— 两者必须用不同视图。
 */
function tokenize(src) {
  const code = [];
  const specifiers = [];
  const strings = [];
  let i = 0;
  let line = 1;
  const n = src.length;

  /**
   * 最近一个"有效字符"（非空白）。v2.1 用 code.join("") 取尾字符判断正则起点，
   * 那是 O(n) 且被调用在每一个 `/` 上，对 minified 大文件是 O(n²)。
   * 这里改成增量维护，行为等价。
   */
  let lastSig = "";

  /** 两视图同推（结构字符、标识符、可执行代码） */
  const push = (c) => {
    code.push(c);
    specifiers.push(c);
    if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") lastSig = c;
  };

  /** 仅 code 掩码为空格；specifiers 原样保留该字符（字符串内容专用） */
  const maskRaw = (ch) => {
    if (ch === "\n") { line++; code.push("\n"); specifiers.push("\n"); return; }
    code.push(" ");
    specifiers.push(ch);
  };

  const isNl = (ch) => ch === "\n";

  /**
   * 单行闭合预检 —— 正则/除号歧义的护栏。
   * 单/双引号若在本行内找不到闭合引号，判为误判的伪字符串，原样当代码放行。
   * 宁可少掩码，不可吞代码（漏报比误报危险）。
   */
  const quotedClosesOnLine = (q) => {
    for (let k = i + 1; k < n; k++) {
      if (src[k] === "\\") { k++; continue; }
      if (src[k] === q) return true;
      if (isNl(src[k])) return false;
    }
    return false;
  };

  /** 单/双引号字符串：内容掩码，specifiers 保留原文 */
  const lexQuoted = (q) => {
    const startLine = line;
    let buf = "";
    push(q); i++;
    while (i < n) {
      const c = src[i];
      if (c === "\\") {
        const e2 = src[i + 1] ?? "";
        buf += c + e2;
        maskRaw("\\");
        maskRaw(e2);
        i += 2;
        continue;
      }
      if (c === q) break;
      if (isNl(c)) { line++; buf += "\n"; code.push("\n"); specifiers.push("\n"); i++; continue; }
      buf += c;
      maskRaw(c);
      i++;
    }
    push(q); i++;
    strings.push({ value: buf, line: startLine, quote: q, hasInterp: /\$\{/.test(buf) });
  };

  /**
   * 模板串：允许跨行；${ 之后递归进入 lexCode(true) 处理表达式。
   * 表达式内的反引号由 lexCode 正常分派，不会再打乱反引号奇偶。
   */
  const lexTemplate = () => {
    const startLine = line;
    let buf = "";
    let hasInterp = false;
    push("`"); i++;
    while (i < n) {
      const c = src[i];
      if (c === "\\") {
        const e2 = src[i + 1] ?? "";
        buf += c + e2;
        maskRaw("\\");
        maskRaw(e2);
        i += 2;
        continue;
      }
      if (c === "`") break;
      if (c === "$" && src[i + 1] === "{") {
        hasInterp = true;
        push("$"); push("{"); i += 2;
        lexCode(true);
        continue;
      }
      if (isNl(c)) { line++; buf += "\n"; code.push("\n"); specifiers.push("\n"); i++; continue; }
      buf += c;
      maskRaw(c);
      i++;
    }
    push("`"); i++;
    strings.push({ value: buf, line: startLine, quote: "`", hasInterp });
  };

  /** 正则字面量：仅在可开始表达式处识别，且必须本行闭合，否则按除号处理 */
  const tryRegex = () => {
    const prevChar = lastSig;
    if (!(prevChar === "" || /[=(,:;[!&|?{}]/.test(prevChar))) return false;
    let k = i + 1;
    let inClass = false;
    let closed = false;
    while (k < n) {
      if (src[k] === "\\") { k += 2; continue; }
      if (isNl(src[k])) break;
      if (src[k] === "[") inClass = true;
      else if (src[k] === "]") inClass = false;
      else if (src[k] === "/" && !inClass) { closed = true; break; }
      k++;
    }
    if (!closed) return false;
    push("/"); i++;
    let inCls = false;
    while (i < n) {
      if (src[i] === "\\") { code.push(" "); specifiers.push(" "); code.push(" "); specifiers.push(" "); i += 2; continue; }
      if (src[i] === "[") inCls = true;
      else if (src[i] === "]") inCls = false;
      else if (src[i] === "/" && !inCls) { push("/"); i++; break; }
      else if (isNl(src[i])) break;
      code.push(" ");
      specifiers.push(src[i]);
      i++;
    }
    return true;
  };

  /** stopAtBrace=true 表示正处于 ${...} 内部：遇配对右花括号即返回模板态 */
  const lexCode = (stopAtBrace) => {
    let braceDepth = 0;
    while (i < n) {
      const c = src[i];
      const d = src[i + 1];
      if (isNl(c)) { line++; push("\n"); i++; continue; }

      if (stopAtBrace) {
        if (c === "}") {
          if (braceDepth === 0) { push("}"); i++; return; }
          braceDepth--; push("}"); i++; continue;
        }
        if (c === "{") { braceDepth++; push("{"); i++; continue; }
      }

      if (c === "/" && d === "/") { while (i < n && !isNl(src[i])) i++; continue; }
      if (c === "/" && d === "*") {
        i += 2;
        while (i < n && !(src[i] === "*" && src[i + 1] === "/")) {
          if (isNl(src[i])) { line++; push("\n"); }
          i++;
        }
        i += 2;
        continue;
      }
      if (c === '"' || c === "'") {
        if (!quotedClosesOnLine(c)) { push(c); i++; continue; }
        lexQuoted(c);
        continue;
      }
      if (c === "`") { lexTemplate(); continue; }
      if (c === "/" && tryRegex()) continue;
      push(c); i++;
    }
  };

  lexCode(false);
  return { code: code.join(""), specifiers: specifiers.join(""), strings };
}

/* ────────────────────── 2. 导入绑定 ────────────────────── */

const norm = (m) => m.replace(/^node:/, "");

function parseBindings(code) {
  const modules = new Map();
  const add = (mod, local, imported) => {
    const m = norm(mod);
    if (!modules.has(m)) modules.set(m, new Map());
    modules.get(m).set(local, imported);
  };
  let m;
  const importRe = /import\s+([\s\S]*?)\s+from\s*["']([^"']+)["']/g;
  while ((m = importRe.exec(code))) {
    const clause = m[1];
    const mod = m[2];
    const braces = clause.match(/\{([^}]*)\}/);
    if (braces) {
      for (const part of braces[1].split(",")) {
        const t = part.trim();
        if (!t) continue;
        const as = t.split(/\s+as\s+/);
        add(mod, (as[1] ?? as[0]).trim(), as[0].trim());
      }
    }
    if (/^\*\s+as\s+/.test(clause)) {
      add(mod, clause.replace(/^\*\s+as\s+/, "").trim(), "*");
    } else {
      const def = clause.replace(/\{[^}]*\}/, "").replace(/,/g, " ").trim().split(/\s+/)[0];
      if (def && def !== "*") add(mod, def, "default");
    }
  }
  const reqNs = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g;
  while ((m = reqNs.exec(code))) add(m[2], m[1], "*");
  const reqDe = /(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g;
  while ((m = reqDe.exec(code))) {
    for (const part of m[1].split(",")) {
      const t = part.trim();
      if (!t) continue;
      const as = t.split(/:\s*/);
      add(m[2], (as[1] ?? as[0]).trim(), as[0].trim());
    }
  }
  return modules;
}

/* ────────────────────── 3. 能力规则 ────────────────────── */

const FS_WRITE = new Set(["writeFile","writeFileSync","appendFile","appendFileSync","createWriteStream","mkdir","mkdirSync","rename","renameSync","copyFile","copyFileSync","truncate","truncateSync","chmod","chmodSync","utimes","utimesSync","outputFile","outputFileSync"]);
const FS_DELETE = new Set(["rm","rmSync","unlink","unlinkSync","rmdir","rmdirSync"]);
const FS_READ = new Set(["readFile","readFileSync","readdir","readdirSync","createReadStream","stat","statSync","lstat","lstatSync","existsSync","access","accessSync","opendir","readlink","realpath"]);
const FS_MODULES = new Set(["fs","fs/promises","graceful-fs","fs-extra"]);
const NET_LIBS = new Set(["axios","got","undici","node-fetch","superagent","request","needle","ky"]);
const INTERNAL_HOST = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])$|\.(internal|invalid|local|test)$|^example\.(com|org)$|^dsh\.internal$/i;

/** 首个实参形态：字面量 / 变量 / 成员访问 */
function argShape(afterParen) {
  const t = afterParen.replace(/^\(\s*/, "");
  const lit = t.match(/^([`"'])([\s\S]*?)\1/);
  if (lit) return { kind: "literal", dynamic: /\$\{/.test(lit[2]), value: lit[2].slice(0, 120) };
  const id = t.match(/^([A-Za-z_$][\w$]*)/);
  if (id) return { kind: "identifier", name: id[1] };
  const mem = t.match(/^([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$.]*)/);
  if (mem) return { kind: "member", name: mem[1] };
  return { kind: "expression" };
}

function scanFile(src, rel) {
  const { code, specifiers, strings } = tokenize(src);
  const lines = code.split("\n");
  /**
   * rawLines —— 与 lines **逐字符等长**的原文视图（注释已删、字符串内容保留）。
   * 用途：判定命令调用的**实参形态**。
   *
   * 为什么不能用 lines（v2.1 的漏报）：lines 里字符串内容全被掩成空格，
   * 于是 argShape 看到的 `"       "` 永远不含 `${`，
   * `dynamic: /\$\{/.test(...)` 恒为 false ——
   * 「动态拼接的命令执行」这一档（唯一判高危的档）**代码上不可达**。
   * 后果：exec(`bash -c ${cmd}`) 会被判成「执行固定命令」medium。
   * 实测：notify L592 模板串、better-sidebar 大量 `cannot list "${path}"` 都被掩成空白。
   *
   * 安全性：rawLines 只用于「取第一个实参的形状」，不做标识符/规则匹配，
   * 因此不会把界面文案里的 fetch/spawn 等词误判成能力（那才是 v2.1 掩码要解决的问题）。
   */
  const rawLines = specifiers.split("\n");
  // 绑定解析用 specifiers 视图（模块名不被掩码），标识符匹配用 code 视图（无字符串噪声）
  const glue = parseBindings(specifiers);
  const shellNames = [];
  const fsNs = [];
  const fsFns = new Map();
  const netNs = [];
  for (const [mod, map] of glue) {
    if (mod === "child_process") for (const [local, imp] of map) shellNames.push({ local, fn: imp === "*" ? null : imp });
    else if (FS_MODULES.has(mod)) for (const [local, imp] of map) imp === "*" ? fsNs.push(local) : fsFns.set(local, imp);
    else if (NET_LIBS.has(mod)) for (const local of map.keys()) netNs.push(local);
  }

  const findings = [];
  const CAP = 6;
  /**
   * 聚合视图（**不受 CAP 截断影响**）——判定必须用它，不能用 findings。
   * 实测缺陷：一个文件里有 6 条静态 exec 之后的第 7 条动态拼接命令
   * 会被 CAP 挡掉，判定层就看不到「动态拼接命令执行」这个高危信号 → 漏报为 medium。
   * 证据条数是为了控制入库体积；等级判定必须看全量事实，两者不能混用。
   */
  const stats = Object.create(null);   // 规则 → 全量命中次数
  const execArgs = new Set();          // command_exec → 出现过的首参形态
  const hostSet = new Set();           // 外部主机（同样不能因截断而丢）
  /**
   * 证据快照必须取自**原文视图**（rawLines）。
   * v2.2 之前取的是 code 视图（字符串已掩码），于是展示给用户的是
   * `const child = spawn("   ", full, {` —— 关键证据（真正执行的程序名）是空白。
   * 对一个以「可复现证据」为卖点的功能，证据不可读等于没有证据。
   */
  const push = (rule, lineNo, _snippet, extra = {}) => {
    // ① 全量聚合先于截断更新 —— 判定层读这里
    stats[rule] = (stats[rule] || 0) + 1;
    if (rule === "command_exec" && extra.argSource) execArgs.add(extra.argSource);
    if (extra.host) hostSet.add(extra.host);
    // ② 证据快照再按 CAP 截断 —— 只影响展示体积
    if (findings.filter((f) => f.rule === rule).length >= CAP) return;
    const raw = rawLines[lineNo] ?? _snippet ?? "";
    findings.push({ rule, file: rel, line: lineNo + 1, snippet: raw.trim().slice(0, 150), ...extra });
  };

  // 该文件里被赋值为绝对 URL 的标识符（用于判定「请求目标」）
  const urlConsts = new Set();
  for (const s of strings) {
    const u = s.value.match(/^https?:\/\/[^\s"'`]+$/);
    if (!u) continue;
    const lineText = lines[s.line - 1] ?? "";
    const assign = lineText.match(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$/);
    if (assign && /_?URL|Url|API|ENDPOINT|BASE|HOST/i.test(assign[1])) urlConsts.add(assign[1]);
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // —— 命令执行 ——
    for (const { local, fn } of shellNames) {
      /**
       * 直接绑定的调用必须排除成员访问：`this.nodePty.spawn(...)` 是 **node-pty** 的
       * spawn，不是 child_process 的。用 `(?<![\w$.])` 挡住 `.` 前缀，
       * 否则会把别的库的能力记到 child_process 名下 —— 证据就不可靠了。
       * node-pty / shell 类的能力改由下面的 shell_pty 规则单独记录（口径可分）。
       */
      const pat = fn
        ? new RegExp(`(?<![\\w$.])${local}\\s*\\(`)
        : new RegExp(`(?:\\bchild_process\\.[A-Za-z]+|(?<![\\w$.])${local}\\s*\\.(execSync|exec|spawnSync|spawn|execFileSync|execFile|fork))\\s*\\(`);
      const h = line.match(pat);
      if (!h) continue;
      const api = fn ?? (h[1] ?? "namespace_call");
      const tail = (rawLines[i] ?? line).slice(h.index + h[0].length - 1);
      const arg = argShape(tail);
      /**
       * 跨行调用补看下一行（实测必需）：`const child = spawn(` 后参数换行书写是
       * 常见风格，只看本行会把首参判成 expression → 误升级为「动态命令执行」。
       * 实测踩坑：Favio8/dsh-plugin-deepeye 的 `spawn(` 在 src/index.ts:470 换行，
       * 被判成高危；补看下一行后能如实取到首参形态。
       */
      let multiline = false;
      if (arg.kind === "expression" && /^\(\s*$/.test(tail)) {
        const probe = "(" + [rawLines[i + 1], rawLines[i + 2]].filter(Boolean).join(" ");
        const a2 = argShape(probe);
        if (a2.kind !== "expression") { Object.assign(arg, a2); multiline = true; }
      }
      /**
       * 参数来源分级（决定风险的关键，不能只看「有没有 spawn」）：
       *   static          = 首参字面量且无模板变量 → 固定程序（如 spawn('git', [...])）
       *   config_or_var   = 首参来自标识符/成员（多来自用户配置或模块级常量）
       *   dynamic_literal = 模板字符串含 ${} → 参数由运行时拼接
       *   expression      = 其他表达式
       * 判「高危」需要知道参数是否来自外部输入，静态扫描无法完全判定，
       * 故只如实记录形态，把结论留给口径层。
       */
      const source = arg.kind === "literal" ? (arg.dynamic ? "dynamic_literal" : "static") : arg.kind === "identifier" || arg.kind === "member" ? "config_or_var" : "expression";
      push("command_exec", i, line, { api, argSource: source, multiline, commandPreview: arg.value ?? arg.name ?? null });
    }

    /**
     * PTY / 终端类成员调用：`<obj>.spawn(...)` 且对象名像 pty/shell/term。
     * 单独成规则而不是并进 command_exec —— 它确实能起进程，但走的是另一个库，
     * 证据来源不同，展示时也应区分（避免把 node-pty 说成 child_process）。
     */
    const ptyM = line.match(/(?<![\w$])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.spawn\s*\(/);
    if (ptyM && /pty|shell|term/i.test(ptyM[1])) {
      push("shell_pty", i, line, { object: ptyM[1] });
    }

    // —— fs ——
    for (const [local, imp] of fsFns) {
      if (!new RegExp(`(?<![\\w$.])${local}\\s*\\(`).test(line)) continue;
      const rule = FS_DELETE.has(imp) ? "fs_delete" : FS_WRITE.has(imp) ? "fs_write" : FS_READ.has(imp) ? "fs_read" : null;
      if (rule) push(rule, i, line, { api: imp, recursive: rule === "fs_delete" && /recursive\s*:\s*true/.test(line) ? true : undefined });
    }
    for (const ns of fsNs) {
      const h = line.match(new RegExp(`\\b${ns}\\.([A-Za-z_$][\\w$]*)\\s*\\(`));
      if (!h) continue;
      const api = h[1];
      const rule = FS_DELETE.has(api) ? "fs_delete" : FS_WRITE.has(api) ? "fs_write" : FS_READ.has(api) ? "fs_read" : null;
      if (rule) push(rule, i, line, { api });
    }

    // —— 网络：只在「请求上下文」里认 URL ——
    /**
     * 请求上下文只认**调用形态**，不认库名裸词。
     * v2.1 首跑踩坑：这里曾写成 `\b(axios|got|...|needle|ky)\b`，
     * 于是 better-sidebar 里 `const needle = query.trim()`、`compileNeedle(needle)`
     * 这类**普通变量名**被批量误判成网络调用（一次扫描刷出 6 条假 finding）。
     * 第三方库一律走 netNs 绑定（由 import 解析得出），不在正则里裸匹配。
     */
    const isReqCtx = /\bfetch\s*\(|https?\.(?:request|get|post)\s*\(|\.request\s*\(|\.(?:get|post)\s*\(\s*["'`]https?:/.test(line);
    if (isReqCtx) {
      for (const s of strings.filter((s) => s.line === i + 1)) {
        const u = s.value.match(/https?:\/\/[^\s"'`]+/);
        if (!u) continue;
        let host;
        try { host = new URL(u[0]).hostname; } catch { continue; }
        if (INTERNAL_HOST.test(host)) continue;
        push("net_request", i, line, { host, url: u[0].slice(0, 120) });
      }
      for (const c of urlConsts) if (new RegExp(`\\b${c}\\b`).test(line)) push("net_request", i, line, { host: "(常量)", via: c });
      push("request_call", i, line, {});
    }
    for (const ns of netNs) if (new RegExp(`\\b${ns}\\s*[.(]`).test(line)) push("request_call", i, line, { lib: ns });

    /**
     * —— 剪贴板：必须区分**读**与**写** ——
     * v2.2 之前一条 `/clipboard|readClipboard|pbcopy|pbpaste/i` 通吃，把
     * `writeClipboard(text)`、`navigator.clipboard.writeText` 也记成「读取剪贴板」。
     * 后果：DSH 侧栏是 webview 前端，大量插件会提供「复制代码块」按钮
     * —— 5 条假 finding（见 omdsh-dev/dsh-genui 实测），
     * 而「往剪贴板写一段文本」与「读走用户刚复制的密码」风险相差一个量级。
     * 两条规则都记录（能力事实完整），但只有**读**参与风险口径。
     */
    if (/(?<![\w$])(readClipboard|pbpaste)\s*\(|clipboard\s*\??\.\s*read(Text)?\s*\(/i.test(line)) push("clipboard_read", i, line, {});
    if (/(?<![\w$])(writeClipboard|pbcopy)\s*\(|clipboard\s*\??\.\s*write(Text)?\s*\(/i.test(line)) push("clipboard_write", i, line, {});
    if (/process\.env\.[A-Z_]*(TOKEN|KEY|SECRET|PASSWORD)/i.test(line)) push("env_secret", i, line, {});
  }
  return { findings, stats, execArgs: [...execArgs], hosts: [...hostSet], stringCount: strings.length,
    // 诊断字段只在 SELF_TEST 下构建，避免生产路径为无用信息付出 O(lines) 开销
    ...(process.env.SELF_TEST ? { _dbg: { shellNames, fsFns: [...fsFns.keys()], fsNs, netNs, linesLen: lines.length, codeLen: code.length, idxExecFile: lines.map((l,i)=>[i,l]).filter(([i,l])=>l.includes("execFile")).slice(0,3) } } : {}),
  };
}

/* ────────────────────── 4. 源码获取 ────────────────────── */

/**
 * 源码缓存目录。默认为本地路径；CI 用 RISK_CACHE_DIR 指向 runner 的临时目录，
 * 随 runner 一起销毁，不需要额外清理。
 */
const CACHE = process.env.RISK_CACHE_DIR || "/tmp/dshrisk-cache";
fs.mkdirSync(CACHE, { recursive: true });

async function curlTo(url, out, token) {
  const args = [
    "-sSL",
    // 大包（creatppt 3.5MB）实测出现过传输中断 ⇒ curl exit 18，
    // 而 execFile 在非零退出时直接抛错，连 HTTP 码都拿不到。
    // `--retry-all-errors` 让「传输中途断开」也进入重试，而不是当成失败。
    "--retry", "4", "--retry-all-errors", "--retry-delay", "2",
    // 🔴 `--retry-max-time` 是**总重试窗口**（不是每次尝试的上限）。
    // 2026-09-24 补：原先只有 `--max-time 180` + 4 次重试，二者组合**没有任何
    // 总量上界** ⇒ 单条最坏 = 5 × 180 + 延迟 ≈ 908 秒（15 分钟）。
    // 实测代价：一轮 20 个里 3 个撞上这个组合（53.8MB 的大仓 + 3 个 curl_err_28），
    // 把并发 3 的槽位全占满 ⇒ 整轮从约 100 秒变成 30 分 24 秒，
    // 16 条正常条目合计才约 270 秒 —— 即 **3/20 的条目吃掉了 94% 的墙钟**。
    // 有了这一条，单条最坏被钉在约 240 秒（窗口 150s + 最后一次尝试 90s）。
    "--retry-max-time", "150",
    "--connect-timeout", "15", "--max-time", "90",
    "-o", out, "-w", "%{http_code}",
  ];
  if (token) args.push("-H", `Authorization: Bearer ${token}`);
  args.push(url);
  try {
    const r = await exec("curl", args, { maxBuffer: 8 * 1024 * 1024 });
    return r.stdout.trim();
  } catch (e) {
    return `curl_err_${e.code ?? "?"}`;
  }
}

/**
 * GitHub 源码 tarball 下载地址。
 *
 * 两条路径（2026-09-23 实测后的结论，别再凭直觉换回去）：
 *   · **带 token** → `api.github.com/repos/{fullName}/tarball`
 *     认证请求额度 **5000/h**，一轮 600 个绰绰有余。
 *   · **无 token** → `codeload.github.com/{fullName}/tar.gz/HEAD`（匿名兜底）
 *
 * 首轮实测（limit=200）：走 api.github.com 且**未带 token** ⇒ 171 个（85.5%）
 * 报 `github tarball HTTP 401`，只有 npm 源那 29 个成功。
 * 改成 codeload 后 ⇒ 150 个报 **404**，失败面没变。
 *
 * ⚠ 两个容易误判的点（本次都踩过）：
 *   1. **本机怎么测都正常**：本机用扫描器同款 curl 参数（含 --retry-all-errors）
 *      测那些「失败」仓库，codeload 与 api 全部 200；CI 内单发诊断同样全 200。
 *      差异只出现在「CI + 批量请求 + 匿名」这个组合里 ⇒ 是**限流（匿名 60/h）**，
 *      不是 URL 写错、也不是仓库不存在。
 *   2. **`github.token` 救不了**：Actions 内置 token 作用域仅当前仓库，
 *      读其他仓库等同匿名。必须用 PAT（workflow 里走 `secrets.GH_TOKEN`）。
 *
 * `HEAD` 用于 codeload 时会解析为默认分支，无需先查 default_branch。
 */
function ghTarballUrl(fullName, hasToken) {
  return hasToken
    ? `https://api.github.com/repos/${fullName}/tarball`
    : `https://codeload.github.com/${fullName}/tar.gz/HEAD`;
}

/** 打上「永久失败」标记的错误对象 —— 供 isPermanentFetchFailure 用**.permanent**判定。 */
function permanentError(msg) {
  const e = new Error(msg);
  e.permanent = true;
  return e;
}

/**
 * 仓库体积闸门（2026-09-24 加）—— 避免单个超大仓库吃掉整轮的并发槽。
 *
 * 实测依据（生产服务器，limit=20 的一轮）：
 *   `DSH-APP/DSHA` 是 **53.8 MB** 的仓库，其 tarball 下载耗时 **904.5 秒**，
 *   最终只扫到 4 个文件。同一轮另有 3 条 `curl_err_28`（下载超时）。
 *   4 条异常条目把并发 3 的槽位占满 ⇒ 整轮 30 分 24 秒，而 16 条正常条目
 *   合计仅约 270 秒。
 *
 * 判据用 GitHub 仓库元数据的 `size` 字段（KB，服务端计算的仓库体积），
 * 一次轻量 API 调用即可，无需先下载才发现巨大。
 *
 * ⚠ 三条刻意的「不拦」：
 *   1. **无 token 时不拦** —— 匿名 api.github.com 只有 60/h，做不了逐条预检；
 *      这种情况下退回「靠 curl 的总重试窗口兜底」（见 curlTo）。
 *   2. **取不到体积时不拦** —— 宁可多花时间扫，也不要凭一次元数据失败就误杀一条。
 *   3. 超限不是「环境侧失败」而是**既成事实** ⇒ 抛永久错误（permanent），
 *      落 no_source 结案、不重排。这一条是**必需的**而不是优化：
 *      阈值定得太高时，超出「单次下载预算」的仓库会**每次都下载失败** ⇒
 *      永远落 scan_error ⇒ 永远重排 ⇒ 无限重试且永远得不到结论。
 *      闸门把「下载不动的」先变成确定结论，才关掉这个死循环。
 *
 * ## 阈值怎么定的（2026-09-24 实测，勿凭感觉改）
 *
 * 实测两个点标定「仓库 size → 真实 tarball」的比例：`dsh_desktop`
 * 112.5MB→18.7MB、`LongHorizon-Harness` 96.3MB→27.4MB 且都还没下完
 * ⇒ **tarball ≈ 0.22 × size**（`size` 含 git 历史，故必然小于它）。
 * 再对队首 150 个采样 size 分布，得到下表（单轮按 400 个算）：
 *
 * | 阈值 | 被判不可分析 | 单轮下载量 | 带宽耗时(@0.76MB/s) |
 * |---|---|---|---|
 * |  50MB | **16.7%** | 0.82 GB | 18 分钟 |
 * | 100MB |  6.0% | 1.48 GB | 32 分钟 |
 * | 200MB |  **2.0%** | 1.86 GB | 41 分钟 |
 *
 * 取 200MB 的理由：50MB 会把 **16.7%** 的插件永久判成「无法判定」——
 * 那些只是仓库历史大、源码完全可分析，属无故损害数据；而 200MB 只影响 2%。
 * 同时 200MB（tarball 约 44MB）**落在单次下载预算内**
 * （`--max-time 90` @0.76MB/s ≈ 68MB tarball ⇒ 仓库约 309MB），
 * 即被放行的条目都能在预算内真正下完，不会退化成上面的死循环。
 * 另有实测的最大仓库 1413MB（tarball 约 310MB）—— 那是必须拦的一类。
 */
const MAX_REPO_MB = parseFloat(process.env.RISK_MAX_REPO_MB || "200");

async function repoSizeKb(fullName, token) {
  try {
    const r = await exec(
      "curl",
      ["-sS", "--max-time", "15", "-H", `Authorization: Bearer ${token}`,
       `https://api.github.com/repos/${fullName}`],
      { maxBuffer: 4 * 1024 * 1024 }
    );
    const kb = Number(JSON.parse(r.stdout).size);
    return Number.isFinite(kb) ? kb : null;
  } catch {
    return null; // 元数据取不到 ⇒ 不拦（见上面第 2 条）
  }
}

async function assertRepoSizeOk(fullName, token) {
  if (!token) return;
  const kb = await repoSizeKb(fullName, token);
  if (kb != null && kb > MAX_REPO_MB * 1024) {
    throw permanentError(
      `仓库体积 ${(kb / 1024).toFixed(1)}MB 超过扫描上限 ${MAX_REPO_MB}MB（避免单条拖垮整轮）`
    );
  }
}

/**
 * 取源码。npm 路径不可用时**自动回落到 GitHub**，并记录回落原因。
 *
 * 为什么必须回落（2026-09-19 实测取证）：站点库里的 `installCheck.pkgName`
 * 是「装前静态校验」推出来的，status=warn 的那批是**猜的**——
 * `@oil-oil/dsh-vision` 在 npm registry 直接 Not found。若照搬 pkgName 去拉包，
 * 要么整条扫描失败，要么（更糟）拉到别人的同名包并把结论挂到这个插件上。
 */
async function fetchSource(t, token) {
  const key = t.pkg ? `npm_${t.pkg.replace(/[@/]/g, "_")}` : `gh_${t.fullName.replace("/", "_")}`;
  const dir = path.join(CACHE, key);
  const metaPath = path.join(dir, ".meta.json");
  if (fs.existsSync(metaPath)) return { dir, ...JSON.parse(fs.readFileSync(metaPath, "utf8")) };

  const finish = async (info) => {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
    await exec("tar", ["-xzf", `${dir}.tgz`, "-C", dir, "--strip-components=1"], { maxBuffer: 32 * 1024 * 1024 });
    fs.writeFileSync(metaPath, JSON.stringify(info));
    return { dir, ...info };
  };

  let pkgFallback = null;
  if (t.pkg) {
    try {
      const metaRes = await exec("curl", ["-sSL", "--max-time", "30", "--retry", "2", `https://registry.npmjs.org/${t.pkg.replace("/", "%2f")}`], { maxBuffer: 64 * 1024 * 1024 });
      const meta = JSON.parse(metaRes.stdout);
      const ver = meta["dist-tags"]?.latest;
      if (!ver) throw new Error(meta.error || "no latest tag");
      const code = await curlTo(`https://registry.npmjs.org/${t.pkg.replace("/", "%2f")}/-/${t.pkg.split("/").pop()}-${ver}.tgz`, `${dir}.tgz`);
      if (code !== "200") throw new Error(`tarball HTTP ${code}`);
      return await finish({ version: ver, source: "npm", requestedPkg: t.pkg });
    } catch (e) {
      pkgFallback = String(e).slice(0, 120);
    }
  }

  await assertRepoSizeOk(t.fullName, token); // 体积闸门：超大仓库直接结案，不下载
  const ghUrl = ghTarballUrl(t.fullName, !!token);
  const code = await curlTo(ghUrl, `${dir}.tgz`, token);
  if (code !== "200") throw new Error(`github tarball HTTP ${code} @ ${ghUrl}${pkgFallback ? ` (npm 回落前错误: ${pkgFallback})` : ""}`);
  return await finish({ version: null, source: "github", requestedPkg: t.pkg, pkgFallback });
}

/**
 * 强制走 GitHub 取源（npm 包下下来但没有可扫源码时的回落路径）。
 * 实测动机：BrokkAi/mjolnir、c3ll256/dsh-toy、eskim2001/dshcloud 的 npm 包里
 * 只有 README + package.json（源码没随包发布），若不回落就只能报「无法判定」。
 */
async function fetchGithubOnly(t, token) {
  const key = `gh_${t.fullName.replace("/", "_")}`;
  const dir = path.join(CACHE, key);
  const metaPath = path.join(dir, ".meta.json");
  if (fs.existsSync(metaPath)) return { dir, ...JSON.parse(fs.readFileSync(metaPath, "utf8")) };
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  await assertRepoSizeOk(t.fullName, token); // 体积闸门（同 fetchSource，见其注释）
  const ghUrl = ghTarballUrl(t.fullName, !!token);
  const code = await curlTo(ghUrl, `${dir}.tgz`, token);
  if (code !== "200") throw new Error(`github tarball HTTP ${code} @ ${ghUrl}`);
  await exec("tar", ["-xzf", `${dir}.tgz`, "-C", dir, "--strip-components=1"], { maxBuffer: 32 * 1024 * 1024 });
  const info = { version: null, source: "github", requestedPkg: t.pkg || null, secondSource: true };
  fs.writeFileSync(metaPath, JSON.stringify(info));
  return { dir, ...info };
}

/* ────────────────────── 5. 运行时入口闭包 ────────────────────── */

const SOURCE_EXT = /\.(m?[jt]s|cjs)$/;

/**
 * 可执行入口（package.json `bin`）。
 * ⚠ 之前完全没考虑 bin，导致「入口闭包为空」误判（实测 firstintent/ccteam：
 *   `module` 指向**未发布**的 src/main.ts，而真正的入口是 `bin.ccteam → dist/main.js`）。
 */
function binFiles(pkgJson) {
  const b = pkgJson.bin;
  const out = new Set();
  const add = (v) => { if (typeof v === "string" && SOURCE_EXT.test(v)) out.add(v.replace(/^\.\//, "")); };
  if (typeof b === "string") add(b);
  else if (b && typeof b === "object") for (const v of Object.values(b)) add(v);
  return out;
}

/**
 * **安装期脚本**引用的文件（preinstall / install / postinstall / prepare）。
 * 为什么必须单独拎出来：这几条是「装包即执行代码」，属于最高危形态，
 * 而其载体常放在被 DEV_SCRIPT_DIR 跳过的 scripts/ 里。
 * 反例（不该纳入）：`build` / `clean` / `lint` / `test` / `fmt` / `prepublishOnly`
 * —— 它们只在开发者本地跑，把它们的 `rm -rf lib` 算成插件风险就是假警（v2.0 踩过）。
 */
const INSTALL_TIME = new Set(["preinstall", "install", "postinstall", "prepare"]);
function installTimeFiles(pkgJson) {
  const S = pkgJson.scripts || {};
  const out = new Set();
  for (const [k, cmd] of Object.entries(S)) {
    if (!INSTALL_TIME.has(k) || typeof cmd !== "string") continue;
    for (const m of cmd.matchAll(/[\w./@-]+\.(?:m?[jt]s|cjs)\b/g)) out.add(m[0].replace(/^\.\//, ""));
  }
  return out;
}

/**
 * ⚠ 这里曾有一个 `devScriptFiles()` + `devOnly` 标记机制，**已删除**（2026-09-19，被实测证伪）。
 *
 * 原设想：「被 build/clean/lint/test 类 npm script 引用的文件 = 开发残留，
 *   在口径层标记为不计风险」——看起来比按目录名跳过更精确。
 *
 * 实测反例（mrRisega/dsh-remote，等级被错误降为 low）：
 *   `"check": "node --check clients/dsh-remote/dsh-bridge.mjs && node --check dsh-setup.mjs && ..."`
 *   一个**语法自检脚本**引用了包内全部真实运行时代码，其中 `dsh-setup.mjs` 本身就是
 *   `bin` 声明的用户入口。于是 4 个真实能力文件全被标 devOnly ⇒
 *   `spawnSync("powershell.exe", ["-EncodedCommand", ...])` / `schtasks` 提权调用
 *   全部不计入等级 ⇒ 输出「低风险」。**又是一次自己制造的漏报。**
 *
 * 结论：「被某个 npm script 引用」**不构成**开发脚本的判据
 *   （node --check / node --test / lint / format 都会引用真实源码）。
 *   控制误报仍回到 v2.3 的机制：DEV_SCRIPT_DIR 按目录收敛扫描范围，
 *   且 bin / 安装期脚本引用一律豁免。宁可少一层"聪明"的标记，不要引入不可预期的不计风险路径。
 */

/** package.json `files` 声明的发布范围（GitHub 源用它把仓库裁剪成「实际会发布的内容」） */
function publishedRoots(pkgJson) {
  const f = pkgJson.files;
  if (!Array.isArray(f)) return null;
  const out = f.filter((x) => typeof x === "string" && !x.startsWith("!")).map((x) => x.replace(/^\.\//, "").replace(/\/$/, ""));
  return out.length ? out : null;
}

/** 从 package.json 求入口文件集合（main / module / exports / browser / dsh.* / bin / 安装期脚本） */
function entryPoints(pkgJson) {
  const out = new Set();
  const pushStr = (v) => { if (typeof v === "string" && SOURCE_EXT.test(v)) out.add(v.replace(/^\.\//, "")); };
  const walk = (v) => {
    if (typeof v === "string") pushStr(v);
    else if (v && typeof v === "object") for (const k of Object.keys(v)) walk(v[k]);
  };
  pushStr(pkgJson.main);
  pushStr(pkgJson.module);
  pushStr(pkgJson.browser);
  walk(pkgJson.exports);
  if (pkgJson.dsh) walk(pkgJson.dsh);
  for (const f of binFiles(pkgJson)) out.add(f);
  for (const f of installTimeFiles(pkgJson)) out.add(f);
  return [...out];
}

/**
 * 从入口出发按相对 import/require 求可达集。
 * 为什么必须做：`scripts/clean-lib.mjs`（构建脚本）、`tsdown.config.ts`（打包配置）
 * 在 npm 包里也能看到，但它们**不在运行时路径**，把它们的 `rm -rf lib` 算成
 * 插件风险就是给用户报假警（v2.0 已踩）。
 */
function reachableFiles(root, entries) {
  const seen = new Set();
  const queue = [...entries];
  const exts = ["", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", "/index.js", "/index.mjs", "/index.ts"];
  while (queue.length) {
    const rel = queue.shift().replace(/^\.\//, "");
    if (seen.has(rel)) continue;
    const abs = path.join(root, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;
    seen.add(rel);
    let src;
    try { src = fs.readFileSync(abs, "utf8"); } catch { continue; }
    for (const m of src.matchAll(/from\s*["'](\.[^"']+)["']|require\(\s*["'](\.[^"']+)["']\s*\)/g)) {
      const spec = m[1] || m[2];
      const base = path.normalize(path.join(path.dirname(rel), spec));
      for (const e of exts) if (fs.existsSync(path.join(root, base + e))) { queue.push(base + e); break; }
    }
  }
  return seen;
}

/**
 * 目录级排除。
 * ⚠ `scripts` 已从此处**移除**（2026-09-19 实测取证）：
 *   TencentCloud/tencentmeeting-cli 的 `files: ["scripts/","dist/"]`，
 *   包内仅有的 2 个 JS 全在 scripts/ 下 —— `bin.tmeet → ./scripts/tmeet.js`、
 *   `postinstall → node scripts/cleanup.js`。按目录名一刀切跳过后：
 *   扫描器报「0 文件、无法判定」，而它其实是**安装期即执行代码**的最高危形态。
 *   dsh 生态里 scripts/ 常放运行时脚本（cpj-dev/dsh-plugin-cc 的 39 个 .mjs 全在 plugins/dsh/scripts/）。
 *   改为按**是否被运行时/安装期引用**决定，见 DEV_SCRIPT_DIR 与 fallbackFiles(root, allow)。
 */
const SKIP_DIR = /(^|\/)(node_modules|\.git|test|tests|__tests__|coverage|\.github|examples?|demo|assets|vendor|third[_-]?party)(\/|$)/i;
/** 构建/开发脚本目录：默认跳过（v2.0 曾把 scripts/clean-lib.mjs 的 `rm -rf lib` 报成插件风险），
 *  但若其中存在被 bin / 安装期脚本引用的文件，则必须纳入 —— 那是能力事实，不是开发残留。 */
/**
 * ⚠ `bin` 曾在 v2.4 被误并入此处，导致一次**自我回归**（2026-09-19）：
 *   bin/ 是「可执行入口」的约定目录，不是开发脚本目录。把它跳过之后
 *   platonai/Browser4 的 bin/version.mjs（含 ``execSync(`npm view "${name}" ...`)``
 *   = dynamic_literal）不再被扫，等级从 high 掉回 medium —— 自己造成了漏报。
 *   bin/ 的正确处理是**纳入扫描**（它本身就是用户入口），不做二次标记。
 */
const DEV_SCRIPT_DIR = /(^|\/)(scripts|tools|\.husky)(\/|$)/i;
const SKIP_FILE = /(\.min\.|\.bundle\.|-bundle\.|\.map$|\.d\.ts$|\.config\.[jt]s$)/i;
const SKIP_CONTENT = /(@license echarts|three\.js|react-dom|monaco-editor|CodeMirror|Copyright jQuery)/i;

function fallbackFiles(root, allow = new Set(), roots = null) {
  const out = [];
  /** allow 白名单（bin / 安装期脚本引用）：命中时即使落在 DEV_SCRIPT_DIR 里也必须扫 */
  const allowedInside = (rel) => [...allow].some((f) => f === rel || f.startsWith(rel + "/"));
  /**
   * GitHub 源是把**整个仓库**打下来的，含大量不会随 npm 发布的内容。
   * 用 `files` 字段（npm 的发布白名单语义）把范围裁到「用户真正会拿到的那部分」，
   * 否则会把仓库里的构建配置/示例/data 都算成插件能力（v2.0 的假警来源）。
   * npm 源的 tarball 本身就只含已发布内容，无需此约束。
   */
  const inRoots = (rel) => !roots || roots.some((r) => rel === r || rel.startsWith(r + "/") || r.startsWith(rel + "/"));
  const walk = (d, depth) => {
    if (out.length >= 600 || depth > 5) return;
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (out.length >= 600) return;
      const rel = path.relative(root, path.join(d, e.name));
      if (e.isDirectory()) {
        if (SKIP_DIR.test(rel) || e.name.startsWith(".")) continue;
        if (DEV_SCRIPT_DIR.test(rel) && !allowedInside(rel)) continue;
        if (!allowedInside(rel) && !inRoots(rel)) continue;
        if (!/^(lib|src|dist|build)$/.test(e.name) && depth > 1) continue;
        walk(path.join(d, e.name), depth + 1);
      } else if (SOURCE_EXT.test(e.name) && !SKIP_FILE.test(e.name)) {
        out.push(rel);
      }
    }
  };
  walk(root, 0);
  return out;
}

/* ────────────────────── 6. 判定（能力事实 → 等级） ────────────────────── */

/**
 * ⚠ 这一层是「口径」，不是「事实」。
 *   扫描器能确定的是**能力事实**（有没有命令执行、读写哪些文件、请求了哪个主机）。
 *   把事实映射成「高/中/低风险」需要一条业务口径：命令参数来自用户配置算不算高危？
 *   只读自己 package.json 算不算「可读取本地文件」？—— 这些是产品决策，
 *   代码里给一个**显式、可审计、可改**的默认映射，改口径只改这里。
 */
const LEVEL_MAP = {
  high: ["插件市场安装脚本（安装即执行代码）", "动态拼接的命令执行（参数含运行时变量）"],
  medium: ["可执行外部命令", "写入本地文件", "读取本地文件", "读取剪贴板", "读取环境变量中的密钥"],
  low: ["仅网络请求 + 读取自身元数据"],
};

function decide(rec) {
  const act = rec.findings || [];
  /**
   * 判定输入取「聚合事实」（rec.ruleCounts / rec.execArgSources），
   * 不取 rec.findings —— findings 是被 CAP 截断过的**展示样本**，
   * 拿它当判定输入会让第 7 条之后的高危信号静默消失（实测缺陷，见 build_v27 说明）。
   * 兼容：聚合缺失时回落到 findings（仅用于单文件自检场景）。
   */
  const counts = rec.ruleCounts
    || act.reduce((m, f) => ((m[f.rule] = (m[f.rule] || 0) + 1), m), {});
  const rules = new Set(Object.keys(counts));
  const argKinds = rec.execArgSources
    || act.filter((f) => f.rule === "command_exec").map((f) => f.argSource);
  const dyn = argKinds.some((a) => a === "dynamic_literal" || a === "expression");
  const dynEvidence = act.filter((f) => f.rule === "command_exec" && (f.argSource === "dynamic_literal" || f.argSource === "expression"));
  const reasons = [];
  let level = "low";
  const raise = (l) => { const o = { low: 0, medium: 1, high: 2 }; if (o[l] > o[level]) level = l; };

  if (rec.installScripts?.length) { raise("high"); reasons.push("安装期脚本"); }
  if (dyn) { raise("high"); reasons.push("动态命令执行"); }
  else if (rules.has("command_exec")) { raise("medium"); reasons.push("可执行固定命令"); }
  if (rules.has("fs_delete")) { raise("medium"); reasons.push("删除本地文件"); }
  if (rules.has("fs_write")) { raise("medium"); reasons.push("写本地文件"); }
  if (rules.has("fs_read")) { raise("medium"); reasons.push("读本地文件"); }
  if (rules.has("clipboard_read")) { raise("medium"); reasons.push("读取剪贴板"); }
  // clipboard_write 是能力事实，不参与升档：向剪贴板写文本不构成敏感数据外泄
  if (rules.has("clipboard_write")) reasons.push("写入剪贴板(不计风险)");
  if (rules.has("env_secret")) { raise("medium"); reasons.push("读取密钥环境变量"); }
  if (rules.has("net_request") || rules.has("request_call")) reasons.push("外部网络");
  const hosts = rec.hostList || [...new Set(act.filter((f) => f.host).map((f) => f.host))];
  return { level, reasons, hosts, dynEvidence: dynEvidence.length };
}

/* ────────────────────── 7. 主流程 ────────────────────── */

const token = process.env.GH_TOKEN || "";

/** 自检入口：SELF_TEST=<文件路径> 时只跑分词/绑定/扫描，用于定位规则失效 */
if (process.env.SELF_TEST) {
  const s = fs.readFileSync(process.env.SELF_TEST, "utf8");
  const { code, specifiers, strings } = tokenize(s);
  const binds = parseBindings(specifiers);
  const r = scanFile(s, "self.js");
  console.log(JSON.stringify({
    srcLen: s.length,
    codeLen: code.length,
    codeSameLineCount: code.split("\n").length === s.split("\n").length,
    hasSpawnInMaskedCode: /spawn\s*\(/.test(code),
    spawnLineSamples: code.split("\n").filter(l=>/\bspawn\s*\(/.test(l)).slice(0,3),
    hasChildProcessImportInMasked: /child_process/.test(code),
    childProcessBinds: [...(binds.get("child_process") || new Map()).entries()],
    fsBinds: [...(binds.get("fs") || binds.get("fs/promises") || new Map()).entries()],
    findings: r.findings,
    findingCount: r.findings.length,
    stats: r.stats,
    execArgs: r.execArgs,
    /**
     * 自检结论要打出来，否则夹具只能验「扫到了什么」，验不了「判成了什么」。
     * 同时给两份结论，让 CAP 缺陷变成一条可复现的对照：
     *   level_aggregate = 修正后（判定读全量聚合）
     *   level_findingsOnly = 修正前（判定读被 CAP 截断的 findings）
     */
    level_aggregate: decide({ findings: r.findings, ruleCounts: r.stats, execArgSources: r.execArgs, hostList: r.hosts }).level,
    level_findingsOnly: (() => {
      const act = r.findings;
      const c = act.reduce((m, f) => ((m[f.rule] = (m[f.rule] || 0) + 1), m), {});
      return decide({ findings: act, ruleCounts: c, execArgSources: act.filter((f) => f.rule === "command_exec").map((f) => f.argSource), hostList: r.hosts }).level;
    })(),
    dbg: r._dbg,
    stringCount: strings.length,
  }, null, 1));
  process.exit(0);
}

/**
 * 扫描单个目标 —— 从原 for 循环体原样提出，**逻辑未做任何改动**。
 * 提出来的目的：本地批量模式与 CI 模式需要共用同一段扫描逻辑，
 * 避免出现「本地验证的」和「CI 跑的」是两份代码（那样回归结论就不成立了）。
 */
async function scanOne(t, token) {
  const t0 = Date.now();
  const rec = { fullName: t.fullName, pkg: t.pkg || null, manual: t.manual || null, ruleVersion: RULE_VERSION };
  try {
    let got = await fetchSource(t, token);
    let dir = got.dir;

    const readPkg = (d) => {
      try { return JSON.parse(fs.readFileSync(path.join(d, "package.json"), "utf8")); } catch { return {}; }
    };
    let pkgJson = readPkg(dir);

    /**
     * 源码范围解析 —— v2.4 起改为「闭包为空/为空集都回落」，并带 npm→GitHub 二级回落。
     *
     * 三条独立缺陷（2026-09-19 实测，样本 53 个里 9 个原本报「0 文件」）：
     *   ① `module` 指向**未发布**的源码（ccteam: module=src/main.ts，实际只发 dist/）
     *      ⇒ 闭包命中 0 个文件，而旧逻辑「entries.length 非 0 就只用闭包」**不会回落**。
     *   ② npm 包里根本没有源码（mjolnir / dsh-toy / dshcloud：只有 README + package.json）
     *      ⇒ 需要回落到 GitHub 仓库取。
     *   ③ `scripts/` 被目录名启发式整片跳过（见 SKIP_DIR 注释）
     *      ⇒ 需靠 bin / 安装期脚本白名单放行。
     */
    /**
     * 源码范围 = 入口闭包 ∪ fallback，**npm 源也做并集**（v2.5 修正）。
     *
     * v2.4 只在 GitHub 源求并集，理由是「npm 包的闭包是完整的」。实测被证伪：
     *   · anbeime/skill：`bin` 只声明 bin/cli.mjs，闭包 1 个文件 ⇒
     *     漏掉包内 dist/cli.mjs（`mkdir`+`writeFile(remote.content)`+`rm`+`rename`，
     *     一个把远端内容装到本地的安装器），等级从 medium 掉到 low —— 纯漏报。
     *   · mrRisega/dsh-remote：`bin` 只有 dsh-setup.mjs，闭包 2 个文件 ⇒
     *     漏掉 packages/dsh-remote-web/lib/index.js 里的
     *     `spawnSync("powershell.exe", ["-EncodedCommand", ...])` / `schtasks` 提权调用。
     * 包会发布入口之外的真实运行时代码（安装器 / CLI / 子包 / 动态 import），
     * 闭包给不了这部分。宁可多扫（由 devOnly + 口径收敛），不可漏扫。
     *
     * GitHub 源额外用 `files` 字段裁剪仓库（仓库 ≠ 发布物）。
     */
    const scanRange = (d, pj, src) => {
      const ent = entryPoints(pj);
      const alw = new Set([...binFiles(pj), ...installTimeFiles(pj)]);
      const roots = src === "github" ? publishedRoots(pj) : null;
      let f = ent.length ? [...reachableFiles(d, ent)] : [];
      let sc = ent.length ? "entry_closure" : "fallback";
      const more = fallbackFiles(d, alw, roots);
      if (more.length) {
        f = [...new Set([...f, ...more])];
        sc = ent.length ? `closure+fallback${roots ? "(files裁剪)" : ""}` : "fallback";
      } else if (ent.length) {
        sc = "entry_closure";
      }
      if (!f.length) { f = fallbackFiles(d, alw); sc = "fallback(no_entry)"; }
      return { files: f, scope: sc, entries: ent };
    };

    let r = scanRange(dir, pkgJson, got.source);
    if (!r.files.length && got.source === "npm") {
      try {
        const g2 = await fetchGithubOnly(t, token);
        const pj2 = readPkg(g2.dir);
        const r2 = scanRange(g2.dir, pj2, "github");
        if (r2.files.length) {
          dir = g2.dir; pkgJson = pj2; r = r2;
          rec.source2 = "github";
          got = { ...g2, source: "npm→github" };
        }
      } catch (e) { rec.githubRetry = String(e).slice(0, 120); }
    }
    rec.source = got.source;
    rec.version = got.version;
    const files = r.files;
    const scope = r.scope;
    rec.scope = scope;
    rec.scannedFiles = files.length;

    const scripts = pkgJson.scripts || {};
    rec.installScripts = Object.keys(scripts).filter((k) => /^(pre|post)?install$/.test(k)).map((k) => `${k}: ${scripts[k]}`);

    // 包身份核验：扫的必须确实是这个插件的包
    const repoUrl = typeof pkgJson.repository === "string" ? pkgJson.repository : pkgJson.repository?.url || "";
    const m = repoUrl.match(/github\.com[/:]([^/]+)\/([^/#.]+)/i);
    rec.repoMatch = m ? `${m[1]}/${m[2]}`.toLowerCase() === rec.fullName.toLowerCase() : "unknown";

    if (!files.length) {
      /**
       * 到这里是真·无源码：包内没有任何 .js/.ts/.mjs/.cjs。
       * 必须**显式标注为无法判定**，绝不允许默认落到 low ——
       * 「因为我们扫不到所以判定它安全」是最危险的一类错误结论。
       * 实测属于这一类的是非 JS 实现（sopaco/deepwiki-rs 是 Rust）或纯文档包。
       */
      rec.auto = "no_source";
      rec.reasons = ["包内无可扫 JS/TS 源码（可能为非 JS 实现或未发布源码），无法判定"];
    } else {
      const findings = [];
      const agg = Object.create(null);      // 规则 → 全量次数
      const execArgs = new Set();           // command_exec 首参形态
      const hostSet = new Set();            // 外部主机
      for (const rel of files) {
        let src;
        try { src = fs.readFileSync(path.join(dir, rel), "utf8"); } catch { continue; }
        if (src.length > 1_500_000 || SKIP_CONTENT.test(src.slice(0, 4000))) continue;
        const one = scanFile(src, rel);
        findings.push(...one.findings);
        for (const [k, v] of Object.entries(one.stats)) agg[k] = (agg[k] || 0) + v;
        one.execArgs.forEach((a) => execArgs.add(a));
        one.hosts.forEach((h) => hostSet.add(h));
      }
      rec.findings = findings;
      /**
       * 全量计数取聚合，不能取 findings ——
       * findings 已被 CAP 截断，之前用它统计会**低估规模**，
       * 与该字段原本的注释「避免展示时低估规模」自相矛盾。
       */
      rec.ruleCounts = agg;
      rec.execArgSources = [...execArgs];
      rec.hostList = [...hostSet];
      const d = decide(rec);
      rec.auto = d.level;
      rec.reasons = d.reasons;
      rec.hosts = d.hosts;
      rec.agree = rec.manual
        ? rec.manual === d.level ? "一致"
          : d.level === "medium" && rec.manual === "low" ? "自动更严"
          : d.level === "low" && rec.manual === "medium" ? "自动更松"
          : "差两级以上"
        : null;
    }
  } catch (e) {
    rec.error = String(e).slice(0, 180);
    // 把「扫描器已判定为永久失败」这件事带出去（如仓库体积超限）。
    // 不能只靠回传时去正则匹配错误串 —— 那是事后猜，而这里是当场知道。
    rec.permanent = !!(e && e.permanent);
    if (rec.auto !== "no_source") rec.auto = "error";
  }
  rec.ms = Date.now() - t0;
  return rec;
}

/* ────────────────────── 8. 本地批量模式（原有用法，保持不变） ────────────────────── */

/**
 * node risk-scan.mjs <targets.json> <out.jsonl>
 * 断点续扫：同一 out.jsonl 里已有的 fullName 跳过。
 */
async function localMain() {
  const targets = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const OUT = process.argv[3] || "/tmp/risk-v2-results.jsonl";
  const MAX = parseInt(process.env.SCAN_MAX || "0", 10);

  const done = new Set();
  if (fs.existsSync(OUT)) {
    for (const l of fs.readFileSync(OUT, "utf8").split("\n")) {
      if (!l.trim()) continue;
      try { done.add(JSON.parse(l).fullName); } catch {}
    }
  } else fs.writeFileSync(OUT, "");

  let n = 0;
  for (const t of targets) {
    if (done.has(t.fullName)) continue;
    if (MAX && n >= MAX) break;
    n++;
    const rec = await scanOne(t, token);
    const icon = rec.agree === "一致" ? "✅" : rec.agree ? "⚠️" : rec.auto === "error" || rec.auto === "no_source" ? "💥" : "  ";
    console.log(`${icon} [${n}] ${rec.fullName} 人工=${rec.manual ?? "-"} 自动=${rec.auto} ${rec.reasons ? "(" + rec.reasons.join("/") + ")" : rec.error || ""} | ${rec.scope} 扫${rec.scannedFiles ?? 0}文件 ${(rec.ms / 1000).toFixed(1)}s`);
    fs.appendFileSync(OUT, JSON.stringify(rec) + "\n");
  }
  console.log(`本轮处理 ${n} 个`);
}

/* ────────────────────── 9. CI 模式（取队列 → 扫描 → 分批回传） ────────────────────── */

/**
 * CI 模式：RISK_CI=1 时启用。
 *
 * 与 localMain 的差别只有「目标从哪来、结论往哪去」——
 * 扫描与判定走的是同一个 scanOne，保证本地验证结论对 CI 成立。
 *
 * 环境变量：
 *   RISK_CI=1            启用 CI 模式
 *   DPH_API_URL          站点地址，默认 https://dpharness.com
 *   DPH_API_TOKEN        鉴权（与站点 RISK_TOKEN / VERIFY_TOKEN 一致）
 *   RISK_LIMIT           本轮最多扫多少个（默认 600，控制 Actions 时长）
 *   RISK_CONCURRENCY     并发数（默认 4；纯网络 IO 为主，但 runner 只有 2 core）
 *   RISK_BATCH           每扫多少个回传一次（默认 20）
 *   RISK_DISK_MIN_MB     磁盘余量低于此值提前收尾（默认 2048）
 *   RISK_CACHE_DIR       源码缓存目录（默认 /tmp/dshrisk-cache）
 */
const CI_MODE = process.env.RISK_CI === "1";
const API = process.env.DPH_API_URL || "https://dpharness.com";
const CI_TOKEN = process.env.RISK_TOKEN || process.env.DPH_API_TOKEN || "";
const CI_LIMIT = parseInt(process.env.RISK_LIMIT || "600", 10);
const CI_CONC = Math.max(1, parseInt(process.env.RISK_CONCURRENCY || "4", 10));
const CI_BATCH = Math.max(1, parseInt(process.env.RISK_BATCH || "20", 10));
const CI_DISK_MIN_MB = Math.max(0, parseInt(process.env.RISK_DISK_MIN_MB || "2048", 10));
const CI_OUT = process.env.RISK_OUT_FILE || "risk-results.jsonl";

/**
 * CI 模式的**前置门**：没有 GitHub 取源凭证就不开工。
 *
 * 依据（2026-09-24）：GitHub 源插件占队列的绝大多数，取源凭证缺失/失效时
 * 它们**不会报错**，只会静默变成 `no_source` 落库 —— 也就是「无法判定」，
 * 既吃掉队列名额（`riskAutoAt` 被写），又在站点上被读成一条结论。
 * 那正是「环境侧失败被记成插件属性」这一类最危险的失效。
 *
 * 与实装验证侧 run-verify.sh 的 GitHub 连通性门同一个取舍：
 * **宁可整轮不跑（2 小时后再来），也不写一批不可信的结论。**
 * 逃生开关：RISK_SKIP_GATE=1（仅在确需强制跑一轮时使用）。
 */
if (CI_MODE && !token && process.env.RISK_SKIP_GATE !== "1") {
  console.error("⛔ 缺少 GH_TOKEN（GitHub 取源凭证）—— 本轮不跑。");
  console.error("   理由：无凭证时 GitHub 取源会整批 401，每个目标都要白跑一次取源");
  console.error("        （约 1 秒/个）并回传一批 scan_error，纯属浪费一轮配额。");
  console.error("        （数据安全上已不会污染：2026-09-24 起 scan_error 不写 riskAutoAt、");
  console.error("         不冒充结论；本门只为省掉这一轮无谓开销。）");
  console.error("   处置：修好 GH_TOKEN；确需强制跑用 RISK_SKIP_GATE=1。");
  process.exit(0);
}

function diskFreeMB(p) {
  try {
    const st = fs.statfsSync(p);
    return Math.round((st.bavail * st.bsize) / 1024 / 1024);
  } catch {
    return null;
  }
}

/** 扫完即清缓存：一次全量要过 8000+ 个包，留着会持续吃磁盘（runner 盘也不大） */
function cleanupOne(dir) {
  try { if (dir) fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  try { if (dir) fs.rmSync(`${dir}.tgz`, { force: true }); } catch {}
}

const ciResults = [];
let ciPending = [];
/** 非 null 表示本轮提前收尾，用于收尾说明 */
let ciEarlyStop = null;

/**
 * 环境侧失败的**永久性判定** —— 决定它是「重试」还是「结案」。
 *
 * 这个区分是 2026-09-24 加的。原实现把所有 `auto === "error"` 一律映射成
 * `no_source` 并照常写 `riskAutoAt`，于是同一次环境抖动造成两处损害：
 *   ① 因凭证/网络失败的插件被**当成结论**落到站点上，而站点对 no_source 的
 *      解释是「已尝试扫描但取不到可分析的 JS/TS 源码」—— 与事实不符；
 *   ② 它们同时被**移出队列**（队列按 riskAutoAt 升序、null 排最前取数），
 *      要等整条队列走完才可能重扫 ⇒ 一次抖动换来半天到数天的覆盖空缺。
 * 2026-09-24 实测现场：600/轮里 435 个报 401，全被记成 no_source。
 *
 * 现在分成两类：
 *   · **永久**（404、包不存在）⇒ no_source，结案，不重排。
 *     404 是插件侧的事实（仓库被删 / 改名 / 转私有），重试多少次都一样。
 *   · **其余**（401/403/429/5xx / 超时 / 解包失败）⇒ scan_error，
 *     **不写 riskAutoAt** ⇒ 自动排回队列，下一轮重试。
 *
 * ⚠ 兜底方向刻意选「重试」而不是「结案」，因为两者代价不对称：
 *   判错成重试 = 多花一点配额，且在站点上**可见**；
 *   判错成结案 = 产出**一条假装有结论的错误数据**，且**不可见**。
 *   本项目对「环境差异被伪装成插件属性」是明令要避免的（见 README）。
 *
 * ⚠ 取码必须先看 GitHub 那一跳：错误串里可能同时含 npm 回落前的旧错误，
 *   例如 `github tarball HTTP 500 @ … (npm 回落前错误: tarball HTTP 404)`
 *   —— 若直接全文搜 404 就会把它误判成永久失败。故按段优先匹配。
 */
function isPermanentFetchFailure(rec) {
  // 扫描器自己下的判定（如「仓库体积超限」）优先 —— 它比事后猜错误串可靠。
  if (rec.permanent) return true;
  const msg = String(rec.error || "");
  const gh = msg.match(/github tarball HTTP (\d+)/);
  if (gh) return gh[1] === "404";
  const npm = msg.match(/tarball HTTP (\d+)/);
  if (npm) return npm[1] === "404";
  // registry 里没有这个包（meta 无 dist-tags.latest，或直接返回 Not found）
  if (/no latest tag|not\s*found/i.test(msg)) return true;
  return false;
}

/**
 * 把 rec 映射成回传体。
 *
 * ⚠ 三处刻意的映射，不要「优化」掉：
 *
 * 1. `auto === "error"` **按失败性质分流**（2026-09-24 改，理由见
 *    isPermanentFetchFailure）：
 *      · 永久失败 → `no_source`（结案，服务端会写 riskAutoAt，从此不再重排）
 *      · 环境侧失败 → `scan_error`（不结案，服务端**不写** riskAutoAt ⇒ 自动重排）
 *    两者都绝不能落到 low —— 那就是凭空说它安全。
 *
 * 2. `facts` 与 `evidence` 分开传。
 *    evidence 是截断后的展示样本（每规则每文件最多 6 条），
 *    facts 是全量聚合。展示层写「共 N 处」必须取 facts，
 *    取 evidence 长度会系统性低估（实测 fs_read 低估 1.91 倍）。
 *
 * 3. `scan_error` 的 reasons 前缀与 `no_source` **必须不同**。
 *    前者是「本次没扫成」，后者是「扫了但这个插件没有可分析源码」——
 *    用户与运维要靠这句文案区分「执行故障」与「插件事实」。
 */
function toReportItem(rec) {
  const level =
    rec.auto === "error"
      ? isPermanentFetchFailure(rec)
        ? "no_source"
        : "scan_error"
      : rec.auto || "no_source";
  const reasons = Array.isArray(rec.reasons) ? [...rec.reasons] : [];
  if (rec.auto === "error" && rec.error) {
    reasons.push(
      level === "scan_error"
        ? `环境侧失败，已自动排回队列重扫（${rec.error}）`
        : `取源不可用（${rec.error}）`
    );
  }
  return {
    fullName: rec.fullName,
    level,
    scope: rec.scope ?? null,
    source: rec.source ?? null,
    reasons,
    evidence: Array.isArray(rec.findings) ? rec.findings : [],
    facts: {
      ruleCounts: rec.ruleCounts || {},
      execArgSources: rec.execArgSources || [],
      hosts: rec.hostList || [],
    },
  };
}

/** 增量回传。失败不抛出 —— 回传失败不该让整轮结果作废（verify 侧同款教训）。 */
async function ciReport(items, label = "回传") {
  if (!CI_TOKEN || !items.length) return false;
  try {
    const res = await fetch(`${API}/api/risk/report`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CI_TOKEN}` },
      body: JSON.stringify({ ranAt: new Date().toISOString(), ruleVersion: RULE_VERSION, results: items }),
    });
    const text = await res.text();
    console.log(`  ${label} ${items.length} 条 → HTTP ${res.status} ${text.slice(0, 120)}`);
    return res.ok;
  } catch (e) {
    console.error(`  ✗ ${label}失败：${String(e).slice(0, 200)}`);
    return false;
  }
}

function ciSaveResults() {
  try {
    fs.writeFileSync(
      CI_OUT,
      JSON.stringify({ ranAt: new Date().toISOString(), ruleVersion: RULE_VERSION, results: ciResults }, null, 1)
    );
    const dist = ciResults.reduce((m, r) => ((m[r.auto] = (m[r.auto] || 0) + 1), m), {});
    console.log(`  结果写入 ${CI_OUT}｜分布 ${JSON.stringify(dist)}`);
  } catch (e) {
    console.error(`  ✗ 写 ${CI_OUT} 失败：${String(e).slice(0, 200)}`);
  }
}

let ciFatalDone = false;
/** 崩溃抢救：把已完成结论回传，别让一整轮白跑。 */
async function ciFatal(where, err) {
  if (ciFatalDone) return;
  ciFatalDone = true;
  console.error(`\n✗ 崩溃于 ${where}：${err?.stack ? err.stack.slice(0, 1000) : String(err).slice(0, 1000)}`);
  try {
    if (ciPending.length) await ciReport(ciPending.splice(0), "[抢救]");
    if (ciResults.length) {
      ciSaveResults();
      await ciReport(ciResults, "[全量补发]");
    }
  } catch {}
  process.exit(1);
}

/** 简单并发池：跑满 CI_CONC 个 worker，保证磁盘检查与回传在同一主线程串行发生 */
async function ciPool(items, worker, conc) {
  let idx = 0;
  const runners = Array.from({ length: Math.min(conc, items.length) }, async () => {
    while (true) {
      const i = idx++;
      if (i >= items.length) return;
      await worker(items[i], i);
    }
  });
  await Promise.all(runners);
}

async function ciMain() {
  process.on("uncaughtException", (e) => void ciFatal("uncaughtException", e));
  process.on("unhandledRejection", (e) => void ciFatal("unhandledRejection", e));

  if (!CI_TOKEN) {
    console.error("❌ DPH_API_TOKEN / RISK_TOKEN 未配置 —— 取队列与回传都无法鉴权");
    process.exit(1);
  }

  console.log(`▶ 规则版本 ${RULE_VERSION}｜并发 ${CI_CONC}｜本轮上限 ${CI_LIMIT}｜缓存 ${CACHE}`);
  console.log(`  磁盘余量 root=${diskFreeMB("/")}MB tmp=${diskFreeMB(os.tmpdir?.() || "/tmp")}MB`);

  let targets = [];
  let queueRemaining = null;
  try {
    const res = await fetch(`${API}/api/risk/queue?limit=${CI_LIMIT}`, {
      headers: { authorization: `Bearer ${CI_TOKEN}` },
    });
    const body = await res.text();
    console.log(`  queue HTTP ${res.status} | ${body.slice(0, 200)}`);
    if (!res.ok) {
      console.error(`❌ queue 请求失败 HTTP ${res.status} —— 401/403 = token 不一致`);
      process.exit(1);
    }
    const parsed = JSON.parse(body);
    targets = parsed.targets || [];
    queueRemaining = parsed.remaining ?? null;
    if (parsed.ruleVersion && parsed.ruleVersion !== RULE_VERSION) {
      console.log(`⚠ 服务端口径版本 ${parsed.ruleVersion} 与本脚本 ${RULE_VERSION} 不一致 —— 请同步 lib/risk-scan-labels.ts`);
    }
  } catch (e) {
    console.error("❌ 取队列异常：", String(e).slice(0, 300));
    process.exit(1);
  }

  console.log(`▶ 本轮待扫 ${targets.length} 个｜队列剩余未扫 ${queueRemaining ?? "?"}`);
  if (!targets.length) {
    // 队列空不是异常（全量扫完了）。正常退出，让 workflow 自然结束、不续跑。
    console.log("  队列已空，无需扫描");
    ciSaveResults();
    return;
  }

  const queue = [...targets];
  await ciPool(queue, async (t) => {
    // 磁盘余量保护：低于阈值就停止派发新任务，已完成的照常回传
    const free = diskFreeMB("/");
    if (free !== null && CI_DISK_MIN_MB > 0 && free < CI_DISK_MIN_MB && !ciEarlyStop) {
      ciEarlyStop = `磁盘余量 ${free}MB 触发阈值 ${CI_DISK_MIN_MB}MB`;
      console.log(`⚠ ${ciEarlyStop} —— 提前收尾并回传已完成部分`);
      return;
    }
    if (ciEarlyStop) return;

    let rec;
    try {
      /**
       * ⚠ 第二个参数是 **GitHub 取源凭证**（`process.env.GH_TOKEN`），
       * 不是回传站点用的 `CI_TOKEN` —— 两者用途完全不同。
       *
       * 2026-09-24 修：此处原为 `scanOne(t, CI_TOKEN)`，把**站点 API token**
       * 当成 GitHub Bearer 发给了 `api.github.com`，于是**每一次** GitHub 取源
       * 都返回 401，而 npm 源那部分照常成功（registry 请求不带这个头）。
       * 现场特征（全部由这一个错配解释，别再往「限流/端点/仓库不存在」上查）：
       *   · 本机跑批量模式全 200（那条路径传的是 `token`）、CI 里单发探针也 200
       *     （探针直接用 `$GH_TOKEN`），只有 CI 批量 401；
       *   · 错误从第 1 条就开始，同秒内 npm 源却成功 ⇒ 不是额度耗尽；
       *   · 曾把端点换成 codeload，失败变成 404 —— 因为**错误的 Authorization 头
       *     照旧被带上**了，换 URL 治不了，反而把根因掩盖成「端点问题」。
       * 代价：600/轮的上限里约 72% 被记成「扫描异常」并落库为 `no_source`，
       *      既吃掉了队列名额，又在站点上被当成「取不到源码」的结论。
       */
      rec = await scanOne(t, token);
    } catch (e) {
      // scanOne 内部已兜住大部分异常；这里兜最后一道，同样按无法判定处理
      rec = {
        fullName: t.fullName,
        pkg: t.pkg || null,
        manual: t.manual || null,
        ruleVersion: RULE_VERSION,
        auto: "error",
        error: String(e).slice(0, 180),
        reasons: [],
      };
    }

    // CI 里缓存用完即清（本地模式保留，靠 .meta.json 复用）
    cleanupOne(path.join(CACHE, t.pkg ? `npm_${String(t.pkg).replace(/[@/]/g, "_")}` : `gh_${String(t.fullName).replace("/", "_")}`));

    ciResults.push(rec);
    ciPending.push(toReportItem(rec));

    const icon = rec.agree === "一致" ? "✅" : rec.agree ? "⚠️" : rec.auto === "error" || rec.auto === "no_source" ? "💥" : "  ";
    console.log(
      `${icon} [${ciResults.length}/${queue.length}] ${rec.fullName} 人工=${rec.manual ?? "-"} 自动=${rec.auto}` +
        ` ${rec.reasons?.length ? "(" + rec.reasons.join("/") + ")" : rec.error || ""} | ${rec.scope ?? "-"} 扫${rec.scannedFiles ?? 0}文件 ${(rec.ms / 1000).toFixed(1)}s`
    );

    if (ciPending.length >= CI_BATCH) await ciReport(ciPending.splice(0));
  }, CI_CONC);

  if (ciPending.length) await ciReport(ciPending.splice(0));
  ciSaveResults();

  const dist = ciResults.reduce((m, r) => ((m[r.auto] = (m[r.auto] || 0) + 1), m), {});
  const agreed = ciResults.filter((r) => r.agree === "一致").length;
  const judged = ciResults.filter((r) => r.manual).length;
  console.log(`\n完成 ${ciResults.length} 个｜分布 ${JSON.stringify(dist)}`);
  // 准确率只在「有人工结论」的子集上算 —— 分母用全部会把数字稀释成无意义
  if (judged) console.log(`人工对照：一致 ${agreed}/${judged}`);
  if (ciEarlyStop) console.log(`⚠ 本轮提前收尾：${ciEarlyStop}——已完成部分已回传，剩余顺延下一轮`);
  console.log(`磁盘余量 root=${diskFreeMB("/")}MB`);
}

if (CI_MODE) {
  ciMain().catch((e) => ciFatal("ciMain", e));
} else {
  localMain().catch((e) => {
    console.error("✗ 本地模式失败：", e?.stack || String(e));
    process.exit(1);
  });
}
