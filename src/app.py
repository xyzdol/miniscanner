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
    'bruteforce': 'modules.bruteforce',  # 新增 bruteforce 模块映射
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
    module_options: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """统一调度各模块的 scan()，并自动识别参数"""
    results = {}
    module_options = module_options or {}
    for m in modules:
        m = m.strip()
        if not m:
            continue
        mod = load_module(m)
        try:
            scan_func = getattr(mod, "scan")
            sig = inspect.signature(scan_func)
            kwargs = {}

            # 常见统一参数（逐项判断模块是否接收）
            if "param_name" in sig.parameters:
                kwargs["param_name"] = param_name
            if "session" in sig.parameters and session is not None:
                kwargs["session"] = session
            if "enable_time" in sig.parameters:
                kwargs["enable_time"] = enable_time
            if "time_threshold" in sig.parameters:
                kwargs["time_threshold"] = time_threshold

            # 从 module_options 中挑选模块接受的参数并传入
            for k, v in (module_options.items() if module_options else {}):
                if k in sig.parameters:
                    kwargs[k] = v

            # 宽松传参：如果模块接受 **kwargs，也将 module_options 全部传进去
            accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            if accepts_kwargs:
                # 合并 kwargs 和 module_options (module_options 优先级低于已经显式设定的 kwargs)
                merged = dict(module_options or {})
                merged.update(kwargs)
                kwargs = merged

            res = scan_func(target, **kwargs)
        except Exception as e:
            res = {"error": str(e)}
        results[m] = res
    return results


# === 构建报告元信息 ===
def build_report_meta(args: argparse.Namespace) -> Dict[str, Any]:
    # 包含 module-specific 参数以便报告记录
    return {
        "generated_at": utc_now_iso(),
        "target": args.target,
        "modules": [x for x in args.modules.split(",") if x],
        "param": args.param,
        "cookie": bool(args.cookie),
        "enable_time": args.enable_time,
        "time_threshold": args.time_threshold,
        # bruteforce-specific
        "login_path": getattr(args, "login_path", None),
        "user_field": getattr(args, "user_field", None),
        "pass_field": getattr(args, "pass_field", None),
        "max_attempts": getattr(args, "max_attempts", None),
        "delay": getattr(args, "delay", None),
        "wordlist": getattr(args, "wordlist", None),
        "success_indicator": getattr(args, "success_indicator", None),
    }


# === CLI 主逻辑 ===
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="MiniScanner - 简易漏洞扫描工具 (教育版)"
    )
    parser.add_argument("--target", required=True, help="目标URL或主机 (可以包含 path，如 http://host/vuln/login.php)")
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

    # ========== bruteforce / auth 模块相关参数（我们在此全部注册） ==========
    parser.add_argument("--login-path", dest="login_path", help="(可选) 登录页面相对路径，例如 /vulnerabilities/brute", default=None)
    parser.add_argument("--user-field", dest="user_field", help="登录表单的用户名字段名 (例如 username)", default="username")
    parser.add_argument("--pass-field", dest="pass_field", help="登录表单的密码字段名 (例如 password)", default="password")
    parser.add_argument("--submit-field", dest="submit_field", help="额外 submit 字段 (JSON 格式字符串，例如 '{\"Login\":\"Login\"}')", default=None)
    parser.add_argument("--success-indicator", dest="success_indicator", help="作为登录成功判定的页面关键字（可选）", default=None)
    parser.add_argument("--max-attempts", dest="max_attempts", type=int, help="暴力破解时最大尝试次数", default=500)
    parser.add_argument("--delay", dest="delay", type=float, help="每次尝试之间的延迟（秒）", default=0.5)
    parser.add_argument("--wordlist", dest="wordlist", help="(可选) 密码字典路径（相对或绝对）", default=None)
    parser.add_argument("--method", dest="method", choices=["GET", "POST"], default="POST", help="登录尝试使用的 HTTP 方法（GET 或 POST）")
    # ========================================================================

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

    # 处理 submit_field JSON 字符串（如果提供）
    submit_field = None
    if args.submit_field:
        try:
            submit_field = json.loads(args.submit_field)
        except Exception:
            # 如果不是合法 JSON，则当作键=值 的单一项来解析（形如 "Login=Login"）
            if "=" in args.submit_field:
                k, v = args.submit_field.split("=", 1)
                submit_field = {k: v}
            else:
                submit_field = None

    # === module_options 收集（将一并传给 scan） ===
    module_options = {
        "login_path": args.login_path,
        "user_field": args.user_field,
        "pass_field": args.pass_field,
        "submit_field": submit_field,
        "success_indicator": args.success_indicator,
        "max_attempts": args.max_attempts,
        "delay": args.delay,
        "wordlist": args.wordlist,
        "method": args.method,
    }

    # === 扫描 ===
    results = run_scan(
        args.target,
        modules,
        param_name=args.param,
        session=session,
        enable_time=args.enable_time,
        time_threshold=args.time_threshold,
        module_options=module_options,
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
