# modules/bruteforce.py
"""
BruteForce 模块（通用增强版）
支持多种登录成功识别逻辑：重定向、文本特征、响应长度、Cookie 改变。
"""

import time
import requests
from typing import Any, Dict, Optional
from utils.helpers import read_wordlist

NAME = "bruteforce"


def _make_url(target: str, login_path: str) -> str:
    if not login_path:
        return target
    if target.endswith("/") and login_path.startswith("/"):
        return target.rstrip("/") + login_path
    return target + login_path


def _post_data(user_field: str, pass_field: str, username: str, password: str, submit_field: Optional[str]):
    data = {user_field: username, pass_field: password}
    if submit_field:
        data[submit_field] = "Login"
    return data


def _contains_any(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(k.lower() in text_lower for k in keywords if k)


def scan(
    target: str,
    session: Optional[requests.Session] = None,
    login_path: str = "",
    user_field: str = "username",
    pass_field: str = "password",
    users_file: str = "",
    passwords_file: str = "",
    max_attempts: int = 200,
    delay: float = 0.0,
    method: str = "POST",
    success_indicator: Optional[str] = None,
    submit_field: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """执行暴力破解扫描。"""
    result = {
        "name": NAME,
        "target": target,
        "detected": False,
        "vulnerable_payload": None,
        "evidence": [],
        "attempts_tried": 0,
        "notes": "",
    }

    sess = session or requests.Session()
    url = _make_url(target, login_path)

    # ===== 通用成功关键词 =====
    default_success_phrases = [
        "welcome", "dashboard", "logout", "sign out", "profile",
        "control panel", "admin panel", "you are logged in",
        "successfully logged", "my account", "secure area",
        "管理", "控制台", "退出登录", "登录成功"
    ]
    if success_indicator:
        default_success_phrases.insert(0, success_indicator)

    # ===== 常见失败关键词（仅作辅助参考，不直接用于成功判定） =====
    fail_phrases = [
        "invalid", "incorrect", "wrong", "failed", "try again",
        "error", "用户名或密码错误", "登录失败"
    ]

    # ===== 字典读取 =====
    try:
        users = read_wordlist(users_file)
    except Exception:
        users = []
    try:
        passwords = read_wordlist(passwords_file)
    except Exception:
        passwords = []

    if not users:
        users = ["admin", "root", "test"]
    if not passwords:
        passwords = ["password", "123456", "admin"]

    # ===== baseline 响应（用于长度差异比较） =====
    try:
        r0 = sess.get(url, timeout=10)
        baseline_len = len(r0.text or "")
        baseline_cookie = dict(sess.cookies)
    except Exception:
        baseline_len = None
        baseline_cookie = {}

    attempts = 0

    for username in users:
        for password in passwords:
            if attempts >= max_attempts:
                result["notes"] = f"达到最大尝试次数 {max_attempts}"
                result["attempts_tried"] = attempts
                return result
            attempts += 1

            data = _post_data(user_field, pass_field, username, password, submit_field)
            start_cookies = dict(sess.cookies)

            try:
                if method.upper() == "GET":
                    resp = sess.get(url, params=data, timeout=10)
                else:
                    resp = sess.post(url, data=data, timeout=10)
            except Exception as e:
                result["evidence"].append({
                    "username": username,
                    "password": password,
                    "url": url,
                    "status_code": None,
                    "time": None,
                    "len": None,
                    "succeeded": False,
                    "reason": f"RequestError: {e}"
                })
                continue

            body = resp.text or ""
            resp_len = len(body)
            new_cookies = dict(sess.cookies)
            succeeded = False
            reason = ""

            # ===== 检测逻辑 =====

            # 1. 重定向检测（登录成功跳转）
            if resp.history and any(
                h.status_code in (301, 302, 303, 307) for h in resp.history
            ):
                succeeded = True
                reason = "Redirect after login"

            # 2. 状态码 302/303 直接跳转
            elif resp.status_code in (301, 302, 303, 307):
                succeeded = True
                reason = f"HTTP {resp.status_code} redirect"

            # 3. 页面包含成功关键词
            elif _contains_any(body, default_success_phrases):
                succeeded = True
                reason = "Matched success keywords"

            # 4. Cookie 变化（新 session id）
            elif len(new_cookies) > len(start_cookies) or new_cookies != start_cookies:
                succeeded = True
                reason = "Session cookie changed"

            # 5. 响应长度变化较大（最后考虑）
            elif baseline_len and abs(resp_len - baseline_len) > 300:
                succeeded = True
                reason = "Significant length difference"

            # ===== 记录证据 =====
            result["evidence"].append({
                "username": username,
                "password": password,
                "url": url,
                "status_code": resp.status_code,
                "time": resp.elapsed.total_seconds() if resp.elapsed else None,
                "len": resp_len,
                "succeeded": succeeded,
                "reason": reason,
            })

            if succeeded:
                result["detected"] = True
                result["vulnerable_payload"] = {"username": username, "password": password}
                result["attempts_tried"] = attempts
                result["notes"] = f"发现有效凭证 {username}:{password} ({reason})"
                return result

            if delay > 0:
                time.sleep(delay)

    result["attempts_tried"] = attempts
    result["notes"] = "未发现有效凭证。"
    return result
