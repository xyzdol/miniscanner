# src/app.py
# MiniScanner CLI 扫描器主程序（增强版）
# 目的：
# - 接受目标 (--target)、模块 (--modules)、以及参数名 (--param)。
# - 动态导入每个检测模块并调用其 scan() 函数。
# - scan() 的接口可为 scan(target) 或 scan(target, param_name)，CLI 会自动判断。
#
# 知识点：
# - argparse 用于命令行解析
# - importlib 动态加载模块
# - inspect.signature() 用于判断函数参数
# - json.dumps(indent=2) 格式化输出结果

import argparse
import importlib
import inspect
import json
import sys

MODULE_MAP = {
    'sql': 'modules.sql_injection',
    'xss': 'modules.xss_scan',
    'port': 'modules.port_scan',
}

def load_module(name: str):
    """根据短名导入对应模块。"""
    mod_path = MODULE_MAP.get(name)
    if not mod_path:
        raise ValueError(f'未知模块: {name}')
    try:
        return importlib.import_module(mod_path)
    except Exception as e:
        raise ImportError(f'导入模块失败 {mod_path}: {e}')

def run_scan(target: str, modules, param_name: str = None):
    """运行指定模块的 scan() 并收集结果。"""
    results = {}
    for m in modules:
        m = m.strip()
        if not m:
            continue
        mod = load_module(m)
        try:
            # 判断模块的 scan() 是否支持 param_name 参数
            scan_func = getattr(mod, 'scan')
            sig = inspect.signature(scan_func)
            if 'param_name' in sig.parameters:
                # 模块支持 param_name，传入 param_name 参数
                res = scan_func(target, param_name=param_name)
            else:
                # 模块不支持 param_name，只传 target
                res = scan_func(target)
        except Exception as e:
            res = {'error': str(e)}
        results[m] = res
    return results

def main(argv=None):
    parser = argparse.ArgumentParser(
        description='MiniScanner - 简易漏洞扫描工具 (教育版)')
    parser.add_argument('--target', required=True, help='目标URL或主机')
    parser.add_argument('--modules', default='sql,xss,port',
                        help='要运行的模块(以逗号分隔)，如 sql,xss,port')
    parser.add_argument('--param', default='q',
                        help='参数名(默认 q)，针对SQLi/XSS等模块')
    args = parser.parse_args(argv)

    modules = [x for x in args.modules.split(',') if x]
    print('目标地址:', args.target)
    print('启用模块:', modules)
    print('参数名:', args.param)

    results = run_scan(args.target, modules, param_name=args.param)
    print('\n=== 扫描结果 ===')
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
