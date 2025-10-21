import argparse
import importlib
# import sys
import json

MODULE_MAP = {
    'sql': 'modules.sql_injection',
    'xss': 'modules.xss_scan',
    'port': 'modules.port_scan',
}

def load_module(name):
    """Dynamically import module by short name like 'sql' or 'xss'."""
    mod_path = MODULE_MAP.get(name)
    if not mod_path:
        raise ValueError(f'Unknown module: {name}. Check MODULE_MAP.')
    try:
        mod = importlib.import_module(mod_path)
        return mod
    except Exception as e:
        # bubble up with context
        raise ImportError(f'Failed to import {mod_path}: {e}') from e

def run_scan(target, modules):
    results = {}
    for m in modules:
        name = m.strip()
        if not name:
            continue
        mod = load_module(name)
        try:
            res = mod.scan(target)
        except Exception as e:
            res = {'error': str(e)}
        results[name] = res
    return results

def main(argv=None):
    parser = argparse.ArgumentParser(description='MiniScanner CLI stub')
    parser.add_argument('--target', required=True, help='Target URL or host')
    parser.add_argument('--modules', default='sql,xss,port', help='Comma-separated modules to run (sql,xss,port)')
    args = parser.parse_args(argv)
    modules = [x for x in args.modules.split(',') if x]
    print('Target:', args.target)
    print('Modules:', modules)
    results = run_scan(args.target, modules)
    print('\n=== Scan Results ===')
    print(json.dumps(results, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
