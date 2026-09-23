// 命令调用形态夹具 —— 用于验证 argShape 的 dynamic 判定是否真的可达
// 每一行代表一种「首参来源」，行号与下方对照表一一对应
import { exec, execSync, spawn, execFile } from "node:child_process";

export function cases(cmd, args, file) {
  exec("git status");                    // L6  静态字面量
  exec(`git status`);                    // L7  模板串（无插值）
  exec(`bash -c ${cmd}`);                // L8  模板串 + 插值  ← 期望 dynamic
  exec(cmd);                             // L9  标识符
  spawn("git", ["status"]);              // L10 静态 + 数组
  execSync(`rm -rf ${cmd}`);             // L11 模板串 + 插值  ← 期望 dynamic
  execFile(file, args);                  // L12 标识符
  exec(`/bin/sh -c "${cmd}"`);           // L13 模板串 + 插值  ← 期望 dynamic
  spawn(`${cmd} --flag`);                // L14 模板串 + 插值  ← 期望 dynamic
  exec(["a", "b"].join(" "));            // L15 表达式
  exec(getCommand());                    // L16 表达式
}
