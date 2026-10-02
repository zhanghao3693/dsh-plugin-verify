#!/usr/bin/env python3
"""
抓取 LMArena（Arena）官方文本榜，转成站点可消费的 JSON 并回写 dpharness.com。

为什么这件事必须放在 GitHub Actions 做：
    lmarena.ai 与官方 HF 数据集（huggingface.co）在中国大陆网络不可达
    （2026-09-16 实测：本机与站点服务器均返回 code=000），
    而站点服务器在腾讯云境内。所以「国外榜」只能由海外 runner 取数后回推站点。
    国内榜（SuperCLUE 的静态 xlsx）境内可直连，由站点自己的定时任务处理。

数据源：官方数据集 lmarena-ai/leaderboard-dataset
    · config = text_style_control（官方默认展示口径，style control 版本）
    · split  = latest（只取最近一期发布的榜单）
    · 过滤  = category == 'overall'（综合榜；该数据集还有 coding / math 等分类）
    经 HF datasets-server 的 /filter 端点做服务端预过滤，避免拉全量 200 万行。

用法：
    python fetch_arena_leaderboard.py --dry-run     # 只抓取并打印，不推送
    python fetch_arena_leaderboard.py               # 抓取并 POST 到站点

环境变量（推送时必需）：
    DPH_API_URL    站点地址，如 https://dpharness.com
    DPH_API_TOKEN  与站点 VERIFY_TOKEN 一致的令牌（GitHub secret）
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

DATASET = "lmarena-ai/leaderboard-dataset"
CONFIG = "text_style_control"
SPLIT = "latest"
WHERE = "\"category\"='overall'"
API = "https://datasets-server.huggingface.co/filter"
PAGE_SIZE = 100
MAX_ROWS = 1000  # 防御性上限，正常 overall 只有几十行
UA = "dpharness-arena-sync/1.0 (+https://dpharness.com)"
REPORT_PATH = "/api/model-ranking/report"

# HF datasets-server 的瞬时失败要重试，不能一次失败就整批放弃。
#
# 背景（2026-09-30 实测）：该服务的 /filter 端点会返回两类瞬时 500 ——
#   · {"error": "the dataset index is loading, this can take a minute"}
#   · {"error": "Authentication check on the Hugging Face Hub failed or timed out. ..."}
# 同一天、相隔一分钟，dry-run 成功而紧接着的正式跑就 500 —— 纯概率性。
# 而本工作流每天只跑一次，/filter 的索引在两次之间会被回收 ⇒ 每次都要现建 ⇒
# 冷启动几乎天天命中。原先「非 2xx 即 raise SystemExit」的写法结果是
# 「每天都失败但没人在看」：2026-09-16~09-29 共 13 次跑批仅 09-20 成功 1 次，
# 线上国外榜因此停在 2026-09-13 的快照整整 17 天（详见 dpharness docs/MODEL_RANKING.md）。
#
# 重试边界：只重试 5xx / 429 / 网络层错误。4xx 一律立即失败 ——
# 那才是真配置错（where 条件或字段名写错），重试只会把它埋掉。
RETRY_ATTEMPTS = 6
RETRY_BASE_DELAY = 30  # 秒；第 n 次失败后等 n*30s（30+60+90+120+150 = 单请求最坏 450s）
#
# ⚠️ 这个「整轮预算」不能定小。曾经定 480s，实测直接踩坑：
# 本脚本要分 5 页拉 409 行（PAGE_SIZE=100），而 HF 冷索引的退避序列本身最长 300s；
# 于是第一页把预算吃光、后面 4 页一次都没得重试 ——
# 日志里明明已经打出「HF 第 5 次尝试成功」，整个 run 仍然失败（2026-09-30 实测）。
# 现在放到 25 分钟，足够「首页退避 + 再有一两页抖动」，同时仍能兜住整轮时长。
RETRY_BUDGET = 25 * 60  # 秒；整轮抓取（含多个分页）累计可用于重试等待的软上限
_RUN_START = time.monotonic()  # 给整轮重试等待封顶，避免无限拖延

# 视为「非开源」的 license 取值；其余非空值都算开放权重
CLOSED_LICENSES = {"proprietary", "unknown", ""}

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
_EN_RE = re.compile(r"^([A-Za-z]{3})[a-z]*\s+(\d{1,2}),?\s+(\d{4})")


def _norm_date(raw: str) -> str:
    """把数据集里的发布日期规范化成 YYYY-MM-DD；认不出来就返回空串。

    2026-10-02 通过 VPN 实地取数确认：该字段当前是 **ISO 格式**（如 "2026-09-30"），
    所以在现有数据上这个规范化其实是空转的。**保留它是为了防 HF 改格式** ——
    一旦变成 "Sep 30, 2026" 这类英文月份，直接做字符串比较会把 "Sep 5, 2026"
    判成比 "Sep 30, 2026" 更新（'5' > '3'），快照日期就会写错。
    站点侧 parseArenaDate() 两种格式都认，口径一致。
    """
    s = (raw or "").strip()
    if not s:
        return ""
    iso = _ISO_RE.match(s)
    if iso:
        return iso.group(0)
    m = _EN_RE.match(s)
    if not m:
        return ""
    try:
        mi = _MONTHS.index(m.group(1)[:3].title())
    except ValueError:
        return ""
    return f"{m.group(3)}-{mi + 1:02d}-{int(m.group(2)):02d}"


def _err_detail(e: urllib.error.HTTPError) -> str:
    """把 HTTP 错误响应的正文转成可读字符串。

    对方返回的常是 JSON，且可能带中文（如站点的「global 条数不足」）。
    直接 decode 出来打印会变成 \\u6761\\u6570 这种转义形式，运维在日志里根本读不了，
    所以能解析成 JSON 就按原文重新序列化。
    """
    raw = e.read().decode("utf-8", "ignore")
    try:
        return json.dumps(json.loads(raw), ensure_ascii=False)[:500]
    except (ValueError, TypeError):
        return raw[:500]


def _is_retryable(e: urllib.error.HTTPError) -> bool:
    """5xx 与 429 是服务端瞬时问题，值得重试；4xx 是调用方写错了，重试无意义。"""
    return e.code >= 500 or e.code == 429


def _get_json(url: str, timeout: int = 60) -> dict:
    """取 JSON，对 HF datasets-server 的瞬时失败做退避重试。

    重试按**单次请求**计：每次调用各自最多 RETRY_ATTEMPTS 次。
    RETRY_BUDGET 只是整轮抓取的宽松软上限（防无限拖延），
    绝不能小到让「前面的分页把预算吃光、后面的分页一次都没得重试」——
    2026-09-30 就是这样把一个本可成功的 run 判失败的（见上方常量处的注释）。
    """
    last = ""
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if attempt > 1:
                    print(f"HF 第 {attempt} 次尝试成功", flush=True)
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # 把 HF 的错误体打出来：字段名或 where 条件写错时，
            # 光看状态码没法定位，必须看到 HF 的原话。
            last = f"HTTP {e.code}: {_err_detail(e)}"
            if not _is_retryable(e):
                break
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = f"{type(e).__name__}: {e}"

        if attempt == RETRY_ATTEMPTS:
            break
        spent = time.monotonic() - _RUN_START
        wait = RETRY_BASE_DELAY * attempt
        if spent + wait > RETRY_BUDGET:
            print(
                f"整轮重试预算已用尽（已耗 {spent:.0f}s / 上限 {RETRY_BUDGET}s），不再重试",
                flush=True,
            )
            break
        print(
            f"HF 瞬时失败（第 {attempt}/{RETRY_ATTEMPTS} 次）：{last}；{wait}s 后重试",
            flush=True,
        )
        time.sleep(wait)

    raise SystemExit(f"请求 HF datasets-server 失败（重试后仍不成功）{last}")


def fetch_rows() -> list[dict]:
    """分页拉取 category=overall 的全部行"""
    rows: list[dict] = []
    offset = 0
    while offset < MAX_ROWS:
        qs = urllib.parse.urlencode(
            {
                "dataset": DATASET,
                "config": CONFIG,
                "split": SPLIT,
                "where": WHERE,
                "offset": offset,
                "length": PAGE_SIZE,
            }
        )
        data = _get_json(f"{API}?{qs}")
        batch = data.get("rows") or []
        if not batch:
            break
        rows.extend((item.get("row") or {}) for item in batch)
        total = data.get("num_rows_total") or 0
        # 按「实际拿到的行数」推进，而不是按 PAGE_SIZE ——
        # 万一服务端单页上限小于我们请求的 length，按 PAGE_SIZE 推进会静默跳过中间的行。
        offset += len(batch)
        if offset >= total:
            break
    return rows


def _num(v) -> float | None:
    return float(v) if isinstance(v, (int, float)) else None


def to_payload(rows: list[dict]) -> dict:
    """HF 行 → 站点 schema（{meta, models:[{rank, model, vendor, license, score, ci, votes}]}）"""
    models: list[dict] = []
    latest = ""
    for r in rows:
        name = str(r.get("model_name") or "").strip()
        rating = _num(r.get("rating"))
        if not name or rating is None:
            continue

        lic = str(r.get("license") or "").strip().lower()
        lo, hi = _num(r.get("rating_lower")), _num(r.get("rating_upper"))
        if lo is not None and hi is not None:
            ci: float | None = round((hi - lo) / 2, 1)
        else:
            ci = None

        votes_raw = _num(r.get("vote_count"))
        norm = _norm_date(str(r.get("leaderboard_publish_date") or ""))
        if norm > latest:
            latest = norm

        models.append(
            {
                "model": name,
                "vendor": (str(r.get("organization") or "").strip() or None),
                "license": "proprietary" if lic in CLOSED_LICENSES else "open",
                "score": round(rating, 2),
                "ci": ci,
                "votes": int(votes_raw) if votes_raw is not None else None,
            }
        )

    # 按分数降序；名次由站点侧在「剔除国产模型」之后重排，这里不预排名次
    models.sort(key=lambda m: m["score"], reverse=True)

    return {
        "meta": {
            "leaderboard": "text",
            # 站点已于 2026-01-28 由 LMArena 更名为 Arena，arena.ai 是主域名，
            # lmarena.ai 仍会 301 过来；这里与站点侧展示口径保持一致。
            "source_url": "https://arena.ai/leaderboard/text",
            "source_dataset": f"{DATASET}:{CONFIG}",
            "last_updated": latest or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        },
        "models": models,
    }


def post_to_site(payload: dict) -> dict:
    base = (os.environ.get("DPH_API_URL") or "").rstrip("/")
    token = os.environ.get("DPH_API_TOKEN") or ""
    if not base or not token:
        raise SystemExit("缺少 DPH_API_URL / DPH_API_TOKEN 环境变量，无法推送（可先用 --dry-run）")

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        base + REPORT_PATH,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {token}",
            "User-Agent": UA,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 把站点返回的原因打出来（校验失败时站点会带 error 字段），避免静默失败
        raise SystemExit(f"回写站点失败 HTTP {e.code}: {_err_detail(e)}") from e


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只抓取并打印摘要，不推送到站点")
    args = ap.parse_args()

    rows = fetch_rows()
    print(f"HF 返回 {len(rows)} 行（category=overall）")
    if len(rows) < 5:
        raise SystemExit(f"行数异常偏少（{len(rows)}），疑似数据集结构或过滤条件变化，中止")

    payload = to_payload(rows)
    models = payload["models"]
    print(f"转换后 {len(models)} 个模型 · 榜单日期 {payload['meta']['last_updated']}")
    # 字段名写错时 to_payload 会把所有行都 skip 掉，最终推一个空榜上去。
    # 与其让站点报 400，不如在这里就说清是「源有数据但转换后没了」。
    if len(models) < 5:
        raise SystemExit(
            f"转换后仅 {len(models)} 个模型（源 {len(rows)} 行），"
            "疑似数据集字段名与预期不符，中止以免回写残缺榜"
        )
    for m in models[:10]:
        print(f"  {m['model'][:44]:<44} {str(m['vendor'])[:18]:<18} {m['score']}")

    if args.dry_run:
        print(json.dumps(payload, ensure_ascii=False)[:1200])
        print("\n--dry-run：未推送")
        return

    resp = post_to_site(payload)
    print("站点回执:", json.dumps(resp, ensure_ascii=False))
    if not resp.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()
