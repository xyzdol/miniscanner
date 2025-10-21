# modules/sql_injection.py
"""
Very small educational SQLi checker (stub).
Behavior:
 - For a given target URL, it will try to append a parameter `q` with
   common SQLi payloads and perform GET requests.
 - It looks for simple SQL error fingerprints in the response body,
   or for obvious differences compared to a baseline (first request).
 - Returns a dictionary with 'detected' boolean and simple 'evidence' list.

WARNING: Only run this against authorized/test targets (DVWA/local).
"""

import requests
import time
PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1' --"
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error",  # generic
]

REQUEST_TIMEOUT = 3.0

def _container_sql_error(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    for sig in SQL_ERRORS:
        if sig in lower:
            return True
    return False

def scan(target: str) -> dict:
    results = {
        'name' : 'sql_injection',
        'target' : target,
        'detected' : False,
        'evidence' : [],
        'notes' : 'Educational stub. Not exhaustive'
    }
    try:
        r0 = requests.get(target, timeout=REQUEST_TIMEOUT)
        baseline_text = r0.text or ""
    except Exception as e:
        results['notes'] = f"Failed baseline request: {e}"
        return results

    for p in PAYLOADS:
        sep = '&' if '?' in target else '?'
        test_url = f"{target}{sep}q={requests.utils.requote_uri(p)}"
        try:
            r = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            body = r.text or ""
        except Exception as e:
            results['evidence'].append({'payload' : p, 'error' : str(e)})
            return results
        if _container_sql_error(body):
            results['detected'] = True
            results['evidence'].append({'payload' : p, 'body' : body})
            break
        if abs(len(body) - len(baseline_text)) > 200:
            results['evidence'].append({'payload': p, 'reason': 'length_difference', 'len_diff': len(body) - len(baseline_text)})

        time.sleep(0.2)

    return results




















