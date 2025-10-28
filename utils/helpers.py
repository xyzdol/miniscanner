# utils/helpers.py
from datetime import datetime, timezone

import os
import datetime
from typing import List, Optional

def utc_now_iso() -> str:
    """返回当前 UTC 时间 ISO 格式（字符串）"""
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def read_wordlist(path: Optional[str]) -> List[str]:
    """
    读取一个 wordlist 文本文件（每行一个条目），返回非空行的列表（strip）。
    path 可以是绝对路径或相对路径。如果文件不存在，抛出 IOError（调用方可捕获）。
    """
    if not path:
        return []
    # 如果 path 是相对并且看起来像简单文件名，允许从模块默认目录尝试（但 app.py 已解析过路径）
    if not os.path.isabs(path):
        # allow direct relative path too
        cand = os.path.join(os.getcwd(), path)
    else:
        cand = path

    lines = []
    with open(cand, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            s = ln.strip()
            if s:
                lines.append(s)
    return lines

# 用于 HTML 报表的一些小工具
def escape(s: str) -> str:
    if s is None:
        return ""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;"))
def safe_join_path(*parts) -> str:
    """
    安全拼接路径（兼容 windows/unix），避免 None 等异常。
    """
    parts = [p for p in parts if p is not None and p != ""]
    if not parts:
        return ""
    return os.path.normpath(os.path.join(*parts))