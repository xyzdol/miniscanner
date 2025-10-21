# modules/xss_scan.py
"""
Very small educational reflective XSS checker.
Behavior:
 - Sends a simple payload as parameter `q` and checks if the payload string
   appears unescaped in the HTTP response body (a naive indicator of reflective XSS).
 - Returns detected flag and evidence.

WARNING: Only run on authorized/test targets.
"""

import requests
import time
import html

REQUEST_TIMEOUT = 3.0

# simple reflective payload (obvious)
PAYLOAD = '<sCrIpT>alert(1)</sCrIpT>'  # mixed case to avoid trivial filters in examples

def scan(target: str) -> dict:
    results = {
        'name': 'xss_scan',
        'target': target,
        'detected': False,
        'evidence': [],
        'notes': 'Naive reflective XSS check (educational).'
    }

    try:
        # build URL with query param q
        sep = '&' if '?' in target else '?'
        test_url = f"{target}{sep}q={requests.utils.requote_uri(PAYLOAD)}"
        r = requests.get(test_url, timeout=REQUEST_TIMEOUT)
        body = r.text or ""
    except Exception as e:
        results['notes'] = f'Failed request: {e}'
        return results

    # naive check: raw payload appears in response
    if PAYLOAD in body:
        results['detected'] = True
        results['evidence'].append({'payload': PAYLOAD, 'reason': 'payload_reflected_raw'})
    else:
        # also check HTML-unescaped presence (e.g., server might encode to &lt;script&gt;)
        if html.escape(PAYLOAD) in body:
            # presence of escaped payload generally indicates it's being sanitized, so not vulnerable
            results['evidence'].append({'payload': PAYLOAD, 'reason': 'payload_escaped'})
        else:
            results['evidence'].append({'payload': PAYLOAD, 'reason': 'no_reflection'})

    # polite delay
    time.sleep(0.2)
    return results
