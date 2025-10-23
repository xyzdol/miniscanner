# modules/xss_scan.py
"""
模块化 XSS 扫描器（从 payload JSON 加载）
保持与 sql 模块相似的返回结构
"""
import json
import os
import time
import html
from urllib.parse import urlencode
import requests

PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "payloads", "xss_payloads.json")

def _load_payloads():
    try:
        with open(PAYLOAD_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # 回退到内置小集合（以防文件缺失）
        return {
            "reflected": ["<script>alert(1)</script>"],
            "dom_script_context": ["');alert(1);//"],
            "event_handlers": ["onerror=alert(1)"]
        }

def _test_payload(session, target, param_name, payload):
    url = f"{target}?{urlencode({param_name: payload})}"
    start = time.time()
    r = session.get(url, timeout=10)
    elapsed = round(time.time() - start, 3)
    return r, elapsed, url

def scan(target: str, param_name: str = "q", session: requests.Session = None, enable_time: bool = False, time_threshold: float = 3.0):
    s = session or requests.Session()
    s.headers.update({"User-Agent": "MiniScanner-XSS/Modular/1.0"})

    payload_groups = _load_payloads()
    evidence = []
    detected = False
    vulnerable_payload = None
    attempts = 0

    # unified detection heuristics
    def analyze_response(r_text):
        # 原始 body，小写
        raw = r_text
        body = raw.lower()
        # html unescape for detecting encoded content
        decoded = html.unescape(body)
        return body, decoded

    for group_name, payload_list in payload_groups.items():
        for payload in payload_list:
            attempts += 1
            try:
                r, elapsed, url = _test_payload(s, target, param_name, payload)
                body, decoded = analyze_response(r.text)

                # detection rules (逐步宽松)
                reason = None
                if payload.lower() in body:
                    reason = "payload_reflected_raw"
                elif html.escape(payload).lower() in body:
                    reason = "payload_reflected_encoded"
                else:
                    # look for JS keywords in decoded content (alert / onerror / onload)
                    if any(k in decoded for k in ["alert(", "onerror=", "onload=", "script>"]):
                        reason = "js_keyword_reflection"

                ev = {
                    "payload": payload,
                    "group": group_name,
                    "method": "GET",
                    "url": url,
                    "status_code": r.status_code,
                    "time": elapsed,
                    "reason": reason
                }
                evidence.append(ev)

                if reason:
                    detected = True
                    vulnerable_payload = payload
                    # stop at first positive (与 sql 风格一致)
                    return {
                        "name": "xss_scan",
                        "target": target,
                        "detected": True,
                        "vulnerable_payload": vulnerable_payload,
                        "evidence": [ev],
                        "attempts_tried": attempts,
                        "notes": "Modular XSS scan (group-based payloads)."
                    }

            except Exception as e:
                evidence.append({"payload": payload, "error": str(e)})
                continue

    return {
        "name": "xss_scan",
        "target": target,
        "detected": detected,
        "vulnerable_payload": vulnerable_payload,
        "evidence": evidence,
        "attempts_tried": attempts,
        "notes": "Modular XSS scan (group-based payloads)."
    }
