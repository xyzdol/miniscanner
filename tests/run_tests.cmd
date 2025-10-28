@echo off
REM tests\run_tests.cmd - Windows cmd 版 smoke test
REM 用法: tests\run_tests.cmd

setlocal

:: 请按需替换下面值
set DVWA_BASE=http://localhost:8898
set SQLI_BASE=http://localhost:8900
set COOKIE_DVWA=PHPSESSID=73srirb08egd4gv1g6vbolfafa; security=low

set BRUTE_TARGET=%DVWA_BASE%/vulnerabilities/brute/
set XSS_TARGET=%DVWA_BASE%/vulnerabilities/xss_d/
set SQL_TARGET=%SQLI_BASE%/sqli-labs/Less-1/

set OUT_BRUTE=%TEMP%\brute_test.json
set OUT_SQL=%TEMP%\sql_test.json
set OUT_XSS=%TEMP%\xss_test.json

echo [run_tests] Running bruteforce...
python -m src.app --target "%BRUTE_TARGET%" --modules bruteforce --cookie "%COOKIE_DVWA%" --user-field username --pass-field password --max-attempts 5 --delay 0.1 --output "%OUT_BRUTE%"
if errorlevel 1 (
  echo bruteforce failed
  exit /b 2
)

echo [run_tests] Running sql...
python -m src.app --target "%SQL_TARGET%" --modules sql --param id --max-attempts 1 --delay 0.1 --output "%OUT_SQL%"
if errorlevel 1 (
  echo sql failed
  exit /b 3
)

echo [run_tests] Running xss...
python -m src.app --target "%XSS_TARGET%" --modules xss --param name --cookie "%COOKIE_DVWA%" --max-attempts 1 --delay 0.1 --output "%OUT_XSS%"
if errorlevel 1 (
  echo xss failed
  exit /b 4
)

echo [run_tests] Verifying JSON files...
python - <<PY
import json,sys,os
paths = {
 "brute": os.environ.get("OUT_BRUTE") or r"%OUT_BRUTE%",
 "sql": os.environ.get("OUT_SQL") or r"%OUT_SQL%",
 "xss": os.environ.get("OUT_XSS") or r"%OUT_XSS%",
}
ok = True
for k,p in paths.items():
    if not os.path.exists(p):
        print(f"[verify] FAIL: {p} not found for {k}")
        ok = False
        continue
    try:
        j = json.load(open(p,"r",encoding="utf-8"))
    except Exception as e:
        print(f"[verify] FAIL: cannot parse {p}: {e}")
        ok = False
        continue
    if "meta" not in j or "results" not in j:
        print(f"[verify] FAIL: {p} missing meta/results")
        ok = False
    else:
        if k not in j["results"]:
            print(f"[verify] WARN: {k} not present under results in {p}")
        print(f"[verify] OK: {p} contains meta/results")
if not ok:
    sys.exit(5)
print("[verify] Smoke tests passed.")
PY

if errorlevel 1 (
  echo Verification failed
  exit /b 5
)

echo All tests passed.
endlocal
