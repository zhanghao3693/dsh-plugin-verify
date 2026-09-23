// 证伪夹具：CAP 截断是否会吃掉后面的 dynamic_literal（高危信号）
// 前 6 条是静态命令，第 7、8 条是动态拼接（本应判 high）
import { exec, spawn } from "node:child_process";

export function run(cmd) {
  exec("git status");              // L6  静态
  exec("git log");                 // L7  静态
  exec("git diff");                // L8  静态
  exec("git branch");              // L9  静态
  exec("git remote");              // L10 静态
  exec("git stash");               // L11 静态
  exec(`bash -c ${cmd}`);          // L12 动态 ← 高危信号
  spawn(`sh -c ${cmd}`);           // L13 动态 ← 高危信号
}
