# reporters/html_reporter.py
from typing import Any, Dict
from utils.helpers import escape
import json
import os

CSS_PATH = os.path.join(os.path.dirname(__file__), "assets", "style.css")

def _load_css():
    try:
        with open(CSS_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""

def generate_html_report(path: str, meta: Dict[str, Any], results: Dict[str, Any]) -> None:
    css = _load_css()
    title = f"MiniScanner Report — {escape(meta.get('target', ''))}"
    now = escape(meta.get("generated_at", ""))

    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='zh-CN'>",
        "<head>",
        f"<meta charset='utf-8'><title>{escape(title)}</title>",
        f"<style>{css}</style>",
        "<script>",
        """
        function toggleDetail(id){
          const e=document.getElementById(id);
          e.style.display=(e.style.display==='none')?'block':'none';
        }
        """,
        "</script>",
        "</head><body>",
        f"<header><h1>{escape(title)}</h1><p class='meta'>报告时间(UTC)：{now}</p></header>",
        "<section class='summary'><h2>扫描摘要</h2><ul>"
    ]

    # summary
    for mod_name, res in results.items():
        vulnerable = isinstance(res, dict) and res.get("detected", False)
        status_class = "vuln" if vulnerable else "safe"
        status_text = "⚠️ 发现漏洞" if vulnerable else "✅ 安全"
        html_parts.append(
            f"<li class='{status_class}'><b>{escape(mod_name)}</b> — {status_text}</li>"
        )

    html_parts.append("</ul></section>")
    html_parts.append("<section class='details'><h2>详细结果</h2>")

    # detail cards
    idx = 0
    for mod_name, res in results.items():
        idx += 1
        try:
            pretty = json.dumps(res, ensure_ascii=False, indent=2)
        except Exception:
            pretty = str(res)
        html_parts.append(
            f"""
            <div class='card'>
              <div class='card-header' onclick="toggleDetail('detail{idx}')">
                <span class='module'>{escape(mod_name)}</span>
                <span class='toggle'>(点击展开/折叠)</span>
              </div>
              <div id='detail{idx}' class='card-body' style='display:none'>
                <pre>{escape(pretty)}</pre>
              </div>
            </div>
            """
        )

    html_parts.append("</section></body></html>")
    html_code = "\n".join(html_parts)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_code)
