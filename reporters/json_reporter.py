# reporters/json_reporter.py
import json
from typing import Any, Dict

def write_json_report(path: str, meta: Dict[str, Any], results: Dict[str, Any]) -> None:
    payload = {
        "meta": meta,
        "results": results
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
