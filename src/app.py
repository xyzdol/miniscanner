# src/app.py
# MiniScanner 主程序（调用各模块 + 报告输出）

import argparse
import importlib
import inspect
import json
import sys
import requests
from typing import Any, Dict

# === 导入辅助与报告模块 ===
from utils.helpers import utc_now_iso
from reporters.json_reporter import write_json_report
from reporters.html_reporter import generate_html_report


# === 模块映射 ===
MODULE_MAP = {
    'sql': 'modules.sql_injection',
    'xss': 'modules.xss_scan',
    'port': 'modules.port_scan',
}


# === 动态加载模块 ===
def load_module(name: str):
    mod_path = MODULE_MAP.get(name)
    if not mod_path:
        raise ValueError(f"未知模块: {name}")
    try:
        return importlib.import_module(mod_path)
    except Exception as e:
        raise ImportError(f"导入模块失败 {mod_path}: {e}")


# === 解析 Cookie 字符串为 Session ===
def make_session_from_cookie_string(cookie_string: str):
    s = requests.Session()
    cookies = {}
    for part in cookie_string.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    jar = requests.cookies.RequestsCookieJar()
    for k, v in cookies.items():
        jar.set(k, v)
    s.cookies.update(jar)
    return s


# === 运行扫描 ===
def run_scan(
    target: str,
    modules,
    param_name: str = None,
    session: requests.Session = None,
    enable_time: bool = False,
    time_threshold: float = 3.0,
) -> Dict[str, Any]:
    """统一调度各模块的 scan()，并自动识别参数"""
    results = {}
    for m in modules:
        m = m.strip()
        if not m:
            continue
        mod = load_module(m)
        try:
            scan_func = getattr(mod, "scan")
            sig = inspect.signature(scan_func)
            kwargs = {}
            if "param_name" in sig.parameters:
                kwargs["param_name"] = param_name
            if "session" in sig.parameters and session is not None:
                kwargs["session"] = session
            if "enable_time" in sig.parameters:
                kwargs["enable_time"] = enable_time
            if "time_threshold" in sig.parameters:
                kwargs["time_threshold"] = time_threshold
            res = scan_func(target, **kwargs)
        except Exception as e:
            res = {"error": str(e)}
        results[m] = res
    return results


# === 构建报告元信息 ===
def build_report_meta(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "generated_at": utc_now_iso(),
        "target": args.target,
        "modules": [x for x in args.modules.split(",") if x],
        "param": args.param,
        "cookie": bool(args.cookie),
        "enable_time": args.enable_time,
        "time_threshold": args.time_threshold,
    }


# === CLI 主逻辑 ===
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="MiniScanner - 简易漏洞扫描工具 (教育版)"
    )
    parser.add_argument("--target", required=True, help="目标URL或主机")
    parser.add_argument(
        "--modules", default="sql,xss,port", help="要运行的模块(以逗号分隔)"
    )
    parser.add_argument("--param", default="q", help="参数名(默认 q)")
    parser.add_argument(
        "--cookie", default=None, help="Cookie 字符串，例如 'PHPSESSID=abc; security=low'"
    )
    parser.add_argument(
        "--enable-time", action="store_true", help="启用 time-based (盲注)检测（默认关闭）"
    )
    parser.add_argument(
        "--time-threshold", type=float, default=3.0, help="time-based 判定阈值（秒），默认 3.0"
    )
    parser.add_argument("--output", default=None, help="输出 JSON 报告路径 (例: report.json)")
    parser.add_argument("--html", default=None, help="输出 HTML 报告路径 (例: report.html)")

    args = parser.parse_args(argv)

    modules = [x for x in args.modules.split(",") if x]
    session = None
    if args.cookie:
        session = make_session_from_cookie_string(args.cookie)

    # === 打印任务信息 ===
    print("目标地址:", args.target)
    print("启用模块:", modules)
    print("参数名:", args.param)
    print("使用 Cookie:", bool(args.cookie))
    print("time-based 启用:", args.enable_time, "阈值(s):", args.time_threshold)
    if args.output:
        print("JSON 输出:", args.output)
    if args.html:
        print("HTML 输出:", args.html)

    # === 扫描 ===
    results = run_scan(
        args.target,
        modules,
        param_name=args.param,
        session=session,
        enable_time=args.enable_time,
        time_threshold=args.time_threshold,
    )

    print("\n=== 扫描结果 ===")
    try:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    except Exception:
        print(results)

    # === 构建 meta 并输出报告 ===
    meta = build_report_meta(args)

    if args.output:
        try:
            write_json_report(args.output, meta, results)
            print(f"已写 JSON 报告到: {args.output}")
        except Exception as e:
            print("写 JSON 报告失败:", e)

    if args.html:
        try:
            generate_html_report(args.html, meta, results)
            print(f"已写 HTML 报告到: {args.html}")
        except Exception as e:
            print("写 HTML 报告失败:", e)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
