# modules/xss_scan.py
# 教学用反射型 XSS 检测模块（增强版）
# 说明（目的）：
# - 发送一个显眼的 payload 到目标页面的参数（默认 param_name='q'），
#   检查返回页面是否包含未转义的 payload 字符串（这是反射型 XSS 的一个简单指示）。
# - 返回统一格式的字典，便于 UI/CLI 展示。
#
# 注意：
# - 这是非常基础的检测：只适用于反射 XSS（页面直接把参数值写回 HTML 中），
#   对 DOM XSS / 被动存储型 XSS / CSP 等不会检测。
# - 请在 DVWA 这类靶场上测试（例如 DVWA 反射XSS路径 /vulnerabilities/xss_r/?name=...）。
#
# 使用示例（DVWA 反射）：
# http://localhost:8080/vulnerabilities/xss_r/?name=aaa

import requests
import html
import time

# 教学用 payload（混合大小写以绕开极其简单的过滤）
PAYLOAD = "<sCrIpT>alert('xss')</sCrIpT>"
TIMEOUT = 4.0

def _payload_reflected_raw(body: str) -> bool:
    """判断 body 中是否包含原始 payload 字符串（未转义）"""
    if not body:
        return False
    return PAYLOAD in body

def _payload_escaped(body: str) -> bool:
    """判断 body 中是否包含被 HTML 转义后的 payload（例如 &lt;script&gt;）"""
    if not body:
        return False
    return html.escape(PAYLOAD) in body

def _make_test_url(base: str, param_name: str, payload: str) -> str:
    from requests.utils import requote_uri
    sep = '&' if '?' in base else '?'
    return f"{base}{sep}{param_name}={requote_uri(payload)}"

def scan(target: str, param_name: str = 'q') -> dict:
    """
    运行一次反射 XSS 测试：
    - target: 页面地址（eg. http://localhost:8080/vulnerabilities/xss_r/）
    - param_name: 参数名（DVWA 常用 name 或 q，根据页面而定）
    """
    res = {
        'name': 'xss_scan',
        'target': target,
        'detected': False,
        'evidence': [],
        'notes': 'Naive reflective XSS check. Only educational.'
    }

    # 构造测试 URL 并请求
    test_url = _make_test_url(target, param_name, PAYLOAD)
    try:
        r = requests.get(test_url, timeout=TIMEOUT)
        body = r.text or ""
    except Exception as e:
        res['notes'] = f'Network error during request: {e}'
        return res

    # 1) 如果响应中直接包含原始 payload，则极可能有反射型 XSS（未转义）
    if _payload_reflected_raw(body):
        res['detected'] = True
        res['evidence'].append({'payload': PAYLOAD, 'reason': 'payload_reflected_raw', 'url': test_url})
        return res

    # 2) 如果包含转义后的 payload，说明页面对输入做了转义（通常是安全的）
    if _payload_escaped(body):
        res['evidence'].append({'payload': PAYLOAD, 'reason': 'payload_escaped', 'url': test_url})
    else:
        # 3) 否则既没反射也没转义，记录为 no_reflection （说明什么都没发生）
        res['evidence'].append({'payload': PAYLOAD, 'reason': 'no_reflection', 'url': test_url})

    # 礼貌等待
    time.sleep(0.2)
    return res
