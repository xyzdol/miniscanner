# src/app.py
# MiniScanner CLI 主程序（增加 --cookie 支持）
import argparse
import importlib
import inspect
import json
import sys
import requests

MODULE_MAP = {
    'sql': 'modules.sql_injection',
    'xss': 'modules.xss_scan',
    'port': 'modules.port_scan',
}

def load_module(name: str):
    mod_path = MODULE_MAP.get(name)
    if not mod_path:
        raise ValueError(f'未知模块: {name}')
    try:
        return importlib.import_module(mod_path)
    except Exception as e:
        raise ImportError(f'导入模块失败 {mod_path}: {e}')

def make_session_from_cookie_string(cookie_string: str):
    """
    cookie_string 示例: "PHPSESSID=abcd; security=low"
    返回一个 requests.Session(), 并把 Cookie header 设置上（以及 cookies）
    """
    s = requests.Session()
    # 将 string 解析为 dict，并设置到 session.cookies
    cookies = {}
    for part in cookie_string.split(';'):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
            cookies[k.strip()] = v.strip()
    # 设置到 session 的 cookies
    jar = requests.cookies.RequestsCookieJar()
    for k, v in cookies.items():
        jar.set(k, v)
    s.cookies.update(jar)
    return s

def run_scan(target: str, modules, param_name: str = None, session: requests.Session = None):
    results = {}
    for m in modules:
        m = m.strip()
        if not m:
            continue
        mod = load_module(m)
        try:
            scan_func = getattr(mod, 'scan')
            sig = inspect.signature(scan_func)
            # 传入 param_name / session（如果模块支持）
            kwargs = {}
            if 'param_name' in sig.parameters:
                kwargs['param_name'] = param_name
            if 'session' in sig.parameters and session is not None:
                kwargs['session'] = session
            # 调用 scan
            res = scan_func(target, **kwargs)
        except Exception as e:
            res = {'error': str(e)}
        results[m] = res
    return results

def main(argv=None):
    parser = argparse.ArgumentParser(description='MiniScanner - 简易漏洞扫描工具 (教育版)')
    parser.add_argument('--target', required=True, help='目标URL或主机')
    parser.add_argument('--modules', default='sql,xss,port', help='要运行的模块(以逗号分隔)')
    parser.add_argument('--param', default='q', help='参数名(默认 q)，针对SQLi/XSS等模块')
    parser.add_argument('--cookie', default=None, help='Cookie 字符串，例如 "PHPSESSID=abc; security=low"（可选）')
    args = parser.parse_args(argv)

    modules = [x for x in args.modules.split(',') if x]
    session = None
    if args.cookie:
        session = make_session_from_cookie_string(args.cookie)

    print('目标地址:', args.target)
    print('启用模块:', modules)
    print('参数名:', args.param)
    print('使用 Cookie:', bool(args.cookie))

    results = run_scan(args.target, modules, param_name=args.param, session=session)
    print('\n=== 扫描结果 ===')
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
