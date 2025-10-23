# modules/xss_scan.py
"""
XSS 检测模块（改进版）
支持反射型、script上下文、HTML转义检测。
"""
import requests
from urllib.parse import urlencode
import html
import time
import re


def scan(target: str, param_name: str = "q", session: requests.Session = None):
    s = session or requests.Session()
    s.headers.update({"User-Agent": "MiniScanner-XSS/3.0"})

    payloads = [
        "<script>alert(1)</script>",
        "<ScRipT>alert(123)</ScRipT>",
        "'><img src=x onerror=alert(1)>",
        "\" onmouseover=alert(1) x=\"",
        "<svg/onload=alert(1)>"
    ]

    detected = False
    vulnerable_payload = None
    evidence = []

    for payload in payloads:
        try:
            url = f"{target}?{urlencode({param_name: payload})}"
            start = time.time()
            r = s.get(url, timeout=10)
            elapsed = round(time.time() - start, 3)
            body_raw = r.text
            body = body_raw.lower()

            # 第一次转义检查
            plain = payload.lower()
            encoded = html.escape(payload).lower()
            double_encoded = html.escape(encoded).lower()
            decoded_body = html.unescape(body)

            # 关键字匹配
            js_keywords = ["alert(", "onerror=", "onload=", "script>", "svg/onload"]

            reason = None
            if plain in body:
                reason = "payload_reflected_raw"
            elif encoded in body or double_encoded in body:
                reason = "payload_reflected_encoded"
            elif any(kw in decoded_body for kw in js_keywords):
                reason = "js_keyword_reflection"

            evidence.append({
                "payload": payload,
                "url": url,
                "status_code": r.status_code,
                "time": elapsed,
                "reason": reason,
                "snippet": decoded_body[:500]  # 前500字符
            })

            if reason:
                detected = True
                vulnerable_payload = payload
                break

        except Exception as e:
            evidence.append({"payload": payload, "error": str(e)})

    return {
        "name": "xss_scan",
        "target": target,
        "detected": detected,
        "vulnerable_payload": vulnerable_payload,
        "evidence": evidence,
        "notes": "Reflected + script-context XSS detection with HTML decode."
    }
