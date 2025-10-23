# utils/helpers.py
from datetime import datetime
import html

def utc_now_iso():
    return datetime.utcnow().isoformat() + "Z"

def escape(s):
    return html.escape(str(s))
