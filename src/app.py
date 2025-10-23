# src/app.py
# MiniScanner CLI 主程序（含报告输出 JSON + 可选 HTML）
import argparse
import importlib
import inspect
import json
import sys
import requests
import datetime
import html
from typing import Any, Dict

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
    s = requests.Session()
    cookies = {}
    for part in cookie_string.split(';'):
        part = part.strip()
        if not part:
            continue
        if '=' in part:
            k, v = part.split('=', 1)
            cookies[k.strip()] = v.strip()
    jar = requests.cookies.RequestsCookieJar()
    for k, v in cookies.items():
        jar.set(k, v)
    s.cookies.update(jar)
    return s

def run_scan(target: str, modules, param_name: str = None, session: requests.Session = None,
             enable_time: bool = False, time_threshold: float = 3.0) -> Dict[str, Any]:
    """
    统一调度各模块的 scan()，并将模块返回的原始 dict 收集。
    支持自动检测模块 scan() 的签名并传入支持的参数。
    """
    results = {}
    for m in modules:
        m = m.strip()
        if not m:
            continue
        mod = load_module(m)
        try:
            scan_func = getattr(mod, 'scan')
            sig = inspect.signature(scan_func)
            kwargs = {}
            if 'param_name' in sig.parameters:
                kwargs['param_name'] = param_name
            if 'session' in sig.parameters and session is not None:
                kwargs['session'] = session
            if 'enable_time' in sig.parameters:
                kwargs['enable_time'] = enable_time
            if 'time_threshold' in sig.parameters:
                kwargs['time_threshold'] = time_threshold
            res = scan_func(target, **kwargs)
        except Exception as e:
            res = {'error': str(e)}
        results[m] = res
    return results

# ----------------- 报告生成器 ----------------- #
def build_report_meta(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "target": args.target,
        "modules": [x for x in args.modules.split(',') if x],
        "param": args.param,
        "cookie": bool(args.cookie),
        "enable_time": args.enable_time,
        "time_threshold": args.time_threshold
    }

def write_json_report(path: str, meta: Dict[str, Any], results: Dict[str, Any]) -> None:
    payload = {
        "meta": meta,
        "results": results
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

def simple_html_escape(s: str) -> str:
    return html.escape(str(s))

def generate_simple_html(path: str, meta: Dict[str, Any], results: Dict[str, Any]) -> None:
    """
    生成一个非常简单的 HTML 报告页，便于课堂演示。
    """
    title = f"MiniScanner Report - {simple_html_escape(meta.get('target'))}"
    now = simple_html_escape(meta.get("generated_at"))
    modules = meta.get("modules", [])
    html_lines = []
    html_lines.append(f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>")
    html_lines.append("<style>body{font-family:Segoe UI,Roboto,Arial;background:#f6f9fc;padding:20px} .card{background:#fff;padding:12px;margin:10px 0;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,0.08)} .ok{color:green}.bad{color:red} pre{white-space:pre-wrap;word-break:break-word}</style>")
    html_lines.append("</head><body>")
    html_lines.append(f"<h2>{title}</h2>")
    html_lines.append(f"<div>Report time (UTC): <strong>{now}</strong></div>")
    html_lines.append(f"<div>Target: <code>{simple_html_escape(meta.get('target'))}</code></div>")
    html_lines.append(f"<div>Modules: {simple_html_escape(','.join(modules))}</div>")
    html_lines.append("<hr/>")

    # summary block
    html_lines.append("<div class='card'><h3>Summary</h3><ul>")
    for mod_name, res in results.items():
        detected = False
        if isinstance(res, dict) and res.get("detected"):
            detected = True
        status = "<span class='bad'>VULNERABLE</span>" if detected else "<span class='ok'>no issue</span>"
        html_lines.append(f"<li><strong>{simple_html_escape(mod_name)}</strong>: {status}</li>")
    html_lines.append("</ul></div>")

    # detail blocks per module
    for mod_name, res in results.items():
        html_lines.append("<div class='card'>")
        html_lines.append(f"<h4>Module: {simple_html_escape(mod_name)}</h4>")
        html_lines.append("<pre>")
        # pretty-print module result safely
        try:
            pretty = json.dumps(res, ensure_ascii=False, indent=2)
        except Exception:
            pretty = str(res)
        html_lines.append(simple_html_escape(pretty))
        html_lines.append("</pre>")
        html_lines.append("</div>")

    html_lines.append("</body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_lines))

# ----------------- CLI 主流程 ----------------- #
def main(argv=None):
    parser = argparse.ArgumentParser(description='MiniScanner - 简易漏洞扫描工具 (教育版)')
    parser.add_argument('--target', required=True, help='目标URL或主机')
    parser.add_argument('--modules', default='sql,xss,port', help='要运行的模块(以逗号分隔)')
    parser.add_argument('--param', default='q', help='参数名(默认 q)，针对SQLi/XSS等模块')
    parser.add_argument('--cookie', default=None, help='Cookie 字符串，例如 "PHPSESSID=abc; security=low"（可选）')
    parser.add_argument('--enable-time', action='store_true', help='启用 time-based (盲注)检测（默认关闭）')
    parser.add_argument('--time-threshold', type=float, default=3.0, help='time-based 判定阈值（秒），默认 3.0')
    parser.add_argument('--output', default=None, help='输出 JSON 报告路径（例如 report.json）')
    parser.add_argument('--html', default=None, help='生成 HTML 报告路径（例如 report.html）')

    args = parser.parse_args(argv)

    modules = [x for x in args.modules.split(',') if x]
    session = None
    if args.cookie:
        session = make_session_from_cookie_string(args.cookie)

    print('目标地址:', args.target)
    print('启用模块:', modules)
    print('参数名:', args.param)
    print('使用 Cookie:', bool(args.cookie))
    print('time-based 启用:', args.enable_time, ' 阈值(s):', args.time_threshold)
    if args.output:
        print('JSON 输出:', args.output)
    if args.html:
        print('HTML 输出:', args.html)

    results = run_scan(args.target, modules, param_name=args.param, session=session,
                       enable_time=args.enable_time, time_threshold=args.time_threshold)

    print('\n=== 扫描结果 ===')
    try:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    except Exception:
        print(results)

    meta = build_report_meta(args)

    if args.output:
        try:
            write_json_report(args.output, meta, results)
            print(f"已写 JSON 报告到: {args.output}")
        except Exception as e:
            print("写 JSON 报告失败:", e)

    if args.html:
        try:
            generate_simple_html(args.html, meta, results)
            print(f"已写 HTML 报告到: {args.html}")
        except Exception as e:
            print("写 HTML 报告失败:", e)

    return 0

if __name__ == '__main__':
    raise SystemExit(main())
