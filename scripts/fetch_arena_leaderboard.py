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

# 视为「非开源」的 license 取值；其余非空值都算开放权重
CLOSED_LICENSES = {"proprietary", "unknown", ""}

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
_EN_RE = re.compile(r"^([A-Za-z]{3})[a-z]*\s+(\d{1,2}),?\s+(\d{4})")


def _norm_date(raw: str) -> str:
    """把数据集里的发布日期规范化成 YYYY-MM-DD；认不出来就返回空串。

    必须规范化后再比大小：该字段可能是 "2026-09-13"，也可能是 "Sep 13, 2026"。
    直接做字符串比较会把 "Sep 5, 2026" 判成比 "Sep 30, 2026" 更新（'5' > '3'），
    进而把快照日期写错。站点侧 parseArenaDate() 也认这两种格式，口径一致。
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


def _get_json(url: str, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 把 HF 的错误体打出来：字段名或 where 条件写错时，
        # 光看状态码没法定位，必须看到 HF 的原话。
        raise SystemExit(f"请求 HF datasets-server 失败 HTTP {e.code}: {_err_detail(e)}") from e


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
        offset += PAGE_SIZE
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
