# src/app.py
# --- BEGIN: ensure project root + src are on sys.path (paste this at very top of src/app.py) ---
# 目的：无论从哪里运行，都能让 `import utils.helpers` 定位到项目根下的 utils 包
import os, sys
from pathlib import Path

# __file__ 指向 src/app.py -> parents[1] 是项目根目录（..）
_THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = str(_THIS_FILE.parents[1])
SRC_DIR = str(_THIS_FILE.parents[0])

# 将 PROJECT_ROOT 和 SRC_DIR 插入 sys.path 的最前面（优先搜索）
for p in (PROJECT_ROOT, SRC_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

# 小调试输出（启动时会打印，运行正确后可以删掉或注释）
# 只打印前 5 项，和 utils 包是否存在于项目根
try:
    _exists = os.path.isdir(os.path.join(PROJECT_ROOT, "utils"))
except Exception:
    _exists = False
print(f"[boot] PROJECT_ROOT={PROJECT_ROOT}")
print(f"[boot] SRC_DIR={SRC_DIR}")
print(f"[boot] utils_exists_in_project_root={_exists}")
print(f"[boot] sys.path[0..4] = {sys.path[:5]}")
# --- END patch ---

# MiniScanner 主程序（调用各模块 + 报告输出）
import argparse
import importlib
import inspect
import json
import sys
import requests
from typing import Any, Dict

from utils.helpers import utc_now_iso
from reporters.json_reporter import write_json_report
from reporters.html_reporter import generate_html_report

# === 模块映射（新增 bruteforce） ===
MODULE_MAP = {
    'sql': 'modules.sql_injection',
    'xss': 'modules.xss_scan',
    'port': 'modules.port_scan',
    'bruteforce': 'modules.bruteforce',
    # future: 'command': 'modules.command_injection'
}

def load_module(name: str):
    mod_path = MODULE_MAP.get(name)
    if not mod_path:
        raise ValueError(f"未知模块: {name}")
    try:
        return importlib.import_module(mod_path)
    except Exception as e:
        raise ImportError(f"导入模块失败 {mod_path}: {e}")

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
                merged = dict(module_options or {})
                merged.update(kwargs)
                kwargs = merged

            res = scan_func(target, **kwargs)
        except Exception as e:
            res = {"error": str(e)}
        results[m] = res
    return results

def build_report_meta(args: argparse.Namespace) -> Dict[str, Any]:
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
        "users_file": getattr(args, "users_file", None),
        "passwords_file": getattr(args, "passwords_file", None),
        "success_indicator": getattr(args, "success_indicator", None),
    }

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="MiniScanner - 简易漏洞扫描工具 (教育版)"
    )
    parser.add_argument("--target", required=True, help="目标URL或主机")
    parser.add_argument("--modules", default="sql,xss,port", help="要运行的模块(以逗号分隔)")
    parser.add_argument("--param", default="q", help="参数名(默认 q)，针对SQLi/XSS等模块")
    parser.add_argument("--cookie", default=None, help='Cookie 字符串，例如 "PHPSESSID=abc; security=low"（可选）')
    parser.add_argument("--enable-time", action="store_true", help="启用时间盲注检测")
    parser.add_argument("--time-threshold", type=float, default=3.0, help="时间盲注阈值(s)")
    # bruteforce specific args (optional)
    # 支持两种 flag 风格: --user-field 和 --user_field（兼容旧命令）
    parser.add_argument("--login-path", "--login_path", dest="login_path", default="", help='bruteforce: 登录提交 path（相对于 target），例如 "/vulnerabilities/brute/"')
    parser.add_argument("--user-field", "--user_field", dest="user_field", default="username", help="bruteforce: 用户名字段")
    parser.add_argument("--pass-field", "--pass_field", dest="pass_field", default="password", help="bruteforce: 密码字段")
    parser.add_argument("--submit-field", "--submit_field", dest="submit_field", default=None, help="表单 submit 字段（如果需要）")
    parser.add_argument("--success-indicator", "--success_indicator", dest="success_indicator", default=None, help="成功判定字符串（可选）")
    parser.add_argument("--max-attempts", "--max_attempts", dest="max_attempts", type=int, default=200, help="bruteforce: 最多尝试次数")
    parser.add_argument("--delay", dest="delay", type=float, default=0.0, help="bruteforce: 每次尝试延迟(s)")
    parser.add_argument("--users-file", "--users_file", dest="users_file", default="users.txt", help="bruteforce: users 文件，路径相对于 modules/payloads/wordlists/")
    parser.add_argument("--passwords-file", "--passwords_file", dest="passwords_file", default="passwords.txt", help="bruteforce: passwords 文件，路径相对于 modules/payloads/wordlists/")
    parser.add_argument("--wordlist", dest="wordlist", default=None, help="bruteforce: 单文件 wordlist（覆盖 users/passwords 的默认行为）")
    parser.add_argument("--method", dest="method", choices=["GET", "POST"], default="POST", help="提交方法（GET/POST）")
    parser.add_argument("--output", default=None, help="写 JSON 报告到文件")
    parser.add_argument("--html", default=None, help="写 HTML 报告到文件")
    args = parser.parse_args(argv)

    modules = [x for x in args.modules.split(",") if x]
    session = None
    if args.cookie:
        session = make_session_from_cookie_string(args.cookie)

    print("目标地址:", args.target)
    print("启用模块:", modules)
    print("参数名:", args.param)
    print("使用 Cookie:", bool(args.cookie))
    print("time-based 启用:", args.enable_time, " 阈值(s):", args.time_threshold)

    # 构造 module_options 并传入 run_scan
    module_options = {
        "login_path": args.login_path,
        "user_field": args.user_field,
        "pass_field": args.pass_field,
        "submit_field": args.submit_field,
        "max_attempts": args.max_attempts,
        "delay": args.delay,
        "users_file": args.users_file,
        "passwords_file": args.passwords_file,
        "success_indicator": args.success_indicator,
        "method": args.method,
    }

    results = run_scan(args.target, modules, param_name=args.param, session=session,
                       enable_time=args.enable_time, time_threshold=args.time_threshold,
                       module_options=module_options)

    # 报告写入（如果需要）
    meta = build_report_meta(args)
    final_report = {"meta": meta, "results": results}
    print("\n=== 扫描结果 ===")
    print(json.dumps(final_report, indent=2, ensure_ascii=False))

    if args.output:
        # write_json_report(path, meta, results)
        write_json_report(args.output, meta, results)
        print("已写 JSON 报告到:", args.output)
    if args.html:
        # generate_html_report(path, meta, results)
        generate_html_report(args.html, meta, results)
        print("已写 HTML 报告到:", args.html)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
