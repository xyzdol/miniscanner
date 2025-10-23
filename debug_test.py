# debug_test.py
# 用来显示模块将要请求的 URL，并进行一次实际请求（可选带 cookie）
# 使用方法:
#   python debug_test.py sql http://dvwa:8898/vulnerabilities/sqli/ id
#   python debug_test.py xss http://dvwa:8898/vulnerabilities/xss_r/ name
#
# 可选: 在命令行末尾追加 cookie 字符串，例如:
#   python debug_test.py sql http://dvwa:8898/vulnerabilities/sqli/ id "PHPSESSID=abcd; security=low"
#
import sys
import importlib

MODULE_MAP = {
    'sql': 'modules.sql_injection',
    'xss': 'modules.xss_scan',
    'port': 'modules.port_scan',
}

def main():
    if len(sys.argv) < 4:
        print("Usage: python debug_test.py <module> <target> <param_name> [cookie_string]")
        sys.exit(1)
    mod_name = sys.argv[1]
    target = sys.argv[2]
    param = sys.argv[3]
    cookie_str = sys.argv[4] if len(sys.argv) >= 5 else None

    mod_path = MODULE_MAP.get(mod_name)
    if not mod_path:
        print("Unknown module:", mod_name)
        sys.exit(1)

    mod = importlib.import_module(mod_path)

    # We will print the URLs the module would test (based on payloads)
    if mod_name == 'sql':
        payloads = getattr(mod, 'PAYLOADS', None)
        if not payloads:
            print("Module has no PAYLOADS attribute.")
            sys.exit(1)
        from requests.utils import requote_uri
        print("----- Constructed test URLs for SQL payloads -----")
        for p in payloads:
            sep = '&' if '?' in target else '?'
            u = f"{target}{sep}{param}={requote_uri(p)}"
            from urllib.parse import unquote
            print(unquote(u))
        # Do one sample request for the first payload and print status & length
        import requests
        headers = {}
        if cookie_str:
            headers['Cookie'] = cookie_str
            print("\nUsing Cookie header:", cookie_str)
        first = payloads[0]
        test_url = f"{target}{'&' if '?' in target else '?'}{param}={requote_uri(first)}"
        print("\nPerforming test request to:", test_url)
        try:
            r = requests.get(test_url, headers=headers, timeout=6)
            print("Status:", r.status_code)
            body = r.text or ""
            print("Body length:", len(body))
            # print a short snippet for inspection
            print("Body (0..800):")
            print(body[:800])
        except Exception as e:
            print("Request failed:", e)

    elif mod_name == 'xss':
        payload = getattr(mod, 'PAYLOAD', None)
        if not payload:
            print("Module has no PAYLOAD")
            sys.exit(1)
        from requests.utils import requote_uri
        from urllib.parse import unquote
        u = f"{target}{'&' if '?' in target else '?'}{param}={requote_uri(payload)}"
        print("Test URL:", unquote(u))
        import requests
        headers = {}
        if cookie_str:
            headers['Cookie'] = cookie_str
            print("\nUsing Cookie header:", cookie_str)
        print("\nPerforming test request to:", u)
        try:
            r = requests.get(u, headers=headers, timeout=6)
            print("Status:", r.status_code)
            body = r.text or ""
            print("Body length:", len(body))
            print("Body (0..800):")
            print(body[:800])
        except Exception as e:
            print("Request failed:", e)
    else:
        print("Module debug support currently only for sql & xss")

if __name__ == '__main__':
    main()
