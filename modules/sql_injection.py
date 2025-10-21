# modules/sql_injection.py
# 教学用 SQL 注入（SQLi）检测模块 (增强版)
# 说明（目的）：
# - 演示如何用“带有典型payload的GET请求 + 错误指纹 / 基线对比”来判断是否可能存在 SQL 注入。
# - 返回一个 dict，包含 name/target/detected/evidence/notes 字段，便于上层统一处理与展示。
#
# 如何做到这个目的（工作原理）：
# 1. 先对目标做一次 baseline 请求（不带payload），保存返回 body 与状态码、长度等基本信息。
# 2. 依次对若干常见 payload 构造测试 URL 发请求（把payload放在名为 q 的参数里，或者你实际页面使用的参数）。
# 3. 检查每次返回的 body 是否包含已知数据库错误指纹（如 MySQL/SQL Server 错误提示），若找到即记录证据；
#    否则用启发式检测（比如页面长度显著变化）作为弱证据。
# 4. 返回发现的第一个确定性证据（教学用）或收集到的弱证据列表。
#
# 注意：本模块非常保守且教学导向，不会做自动化 exploit/盲注/多线程扫描。只做低速、简单的检测。
# 使用示例（DVWA）：
# - SQLi 演示页面（本机 DVWA）常见路径示例：
#   http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit
#   上面示例中参数名是 id；本模块默认使用参数名 q 若你用 DVWA 请替换为 id。
#
# 返回格式（示例）：
# {
#   'name': 'sql_injection',
#   'target': 'http://localhost:8080/vulnerabilities/sqli/',
#   'detected': True/False,
#   'evidence': [ {'payload': "...", 'reason': 'sql_error_signature', ...}, ... ],
#   'notes': '...'
# }

import requests
import time
from typing import List

# 教学用 payload（少而精）
PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1' --",
    "' OR 'a'='a"
]

# 常见的 SQL 错误指纹（小写匹配）
SQL_ERROR_SIGS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax",     # 宽松匹配
    "mysql_fetch",    # php/mysqL 函数错误迹象
    "syntax error"
]

TIMEOUT = 4.0

def _has_sql_error(text: str) -> bool:
    """判断响应文本是否包含数据库错误指纹（小写匹配）"""
    if not text:
        return False
    l = text.lower()
    for sig in SQL_ERROR_SIGS:
        if sig in l:
            return True
    return False

def _make_test_url(base: str, param_name: str, payload: str) -> str:
    """
    构造测试 URL：
    - 如果 base 已含有 ? 则使用 &param=payload 否则使用 ?param=payload
    - requests.utils.requote_uri 简单对 payload 做 URL 转义
    """
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}"

def scan(target: str, param_name: str = 'q') -> dict:
    """
    运行扫描：
    - target: 页面地址（例如 http://localhost:8080/vulnerabilities/sqli/）
    - param_name: 要插入 payload 的参数名（DVWA 常用 'id'，示例默认 'q'）
    返回：结果字典
    """
    res = {
        'name': 'sql_injection',
        'target': target,
        'detected': False,
        'evidence': [],
        'notes': 'Educational scan: use param_name to match real page (e.g., id for DVWA).'
    }

    # 1) baseline 请求：拿到 baseline body 和长度
    try:
        r0 = requests.get(target, timeout=TIMEOUT)
        baseline_body = r0.text or ""
        baseline_len = len(baseline_body)
        baseline_status = r0.status_code
    except Exception as e:
        res['notes'] = f'Baseline request failed: {e}'
        return res

    # 2) 对每个 payload 尝试
    for payload in PAYLOADS:
        test_url = _make_test_url(target, param_name, payload)
        try:
            r = requests.get(test_url, timeout=TIMEOUT)
            body = r.text or ""
            status = r.status_code
        except Exception as e:
            # 记录网络错误作为 evidence，但不认为是漏洞
            res['evidence'].append({'payload': payload, 'reason': 'network_error', 'error': str(e)})
            continue

        # 3) 直接匹配错误指纹 -> 确定性证据
        if _has_sql_error(body):
            res['detected'] = True
            res['evidence'].append({'payload': payload, 'reason': 'sql_error_signature', 'url': test_url})
            # 教学用，遇到第一个确定性证据就返回
            return res

        # 4) 启发式：响应长度显著变化（弱证据）
        if abs(len(body) - baseline_len) > 300:
            res['evidence'].append({'payload': payload, 'reason': 'body_length_diff', 'len_diff': len(body) - baseline_len, 'url': test_url})

        # 轻微等待，礼貌请求
        time.sleep(0.2)

    return res
