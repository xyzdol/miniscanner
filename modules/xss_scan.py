# modules/xss_scan.py
import requests
import html
import time
from typing import Optional

PAYLOAD = "<sCrIpT>alert('xss')</sCrIpT>"
TIMEOUT = 4.0

def _payload_reflected_raw(body: str) -> bool:
    if not body:
        return False
    return PAYLOAD in body

def _payload_escaped(body: str) -> bool:
    if not body:
        return False
    return html.escape(PAYLOAD) in body

def _make_test_url(base: str, param_name: str, payload: str) -> str:
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}"

def scan(target: str, param_name: str = 'q', session: Optional[requests.Session] = None) -> dict:
    res = {
        'name': 'xss_scan',
        'target': target,
        'detected': False,
        'evidence': [],
        'notes': 'Naive reflective XSS check.'
    }

    requester = session if session is not None else requests

    test_url = _make_test_url(target, param_name, PAYLOAD)
    try:
        r = requester.get(test_url, timeout=TIMEOUT)
        body = r.text or ""
    except Exception as e:
        res['notes'] = f'Network error: {e}'
        return res

    if _payload_reflected_raw(body):
        res['detected'] = True
        res['evidence'].append({'payload': PAYLOAD, 'reason': 'payload_reflected_raw', 'url': test_url})
        return res

    if _payload_escaped(body):
        res['evidence'].append({'payload': PAYLOAD, 'reason': 'payload_escaped', 'url': test_url})
    else:
        res['evidence'].append({'payload': PAYLOAD, 'reason': 'no_reflection', 'url': test_url})

    time.sleep(0.2)
    return res
