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

    html_head = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{escape(title)}</title>
<style>{css}</style>
</head>
<body>
<header><h1>{escape(title)}</h1><div class="meta">Time: {now}</div></header>

<div class="controls">
  <input id="search" placeholder="搜索模块名或 payload ..." />
  <button onclick="filterOnlyVuln()">只看有漏洞</button>
  <button onclick="expandAll()">全部展开</button>
  <button onclick="collapseAll()">全部折叠</button>
</div>

<div id="content">
"""

    html_tail = """
</div>

<script>
function toggle(id){
  const e = document.getElementById(id);
  e.style.display = (e.style.display === 'none') ? 'block' : 'none';
}
function expandAll(){
  document.querySelectorAll('.card-body').forEach(e => e.style.display='block');
}
function collapseAll(){
  document.querySelectorAll('.card-body').forEach(e => e.style.display='none');
}
function filterOnlyVuln(){
  document.querySelectorAll('.card').forEach(card=>{
    card.style.display = card.dataset.vuln === 'true' ? 'block' : 'none';
  });
}
document.getElementById('search').addEventListener('input', function(e){
  const q = e.target.value.toLowerCase();
  document.querySelectorAll('.card').forEach(card=>{
    const text = card.innerText.toLowerCase();
    card.style.display = text.includes(q) ? 'block' : 'none';
  });
});
function copyText(id){
  const t = document.getElementById(id).innerText;
  navigator.clipboard.writeText(t);
  alert('已复制到剪贴板');
}
</script>

</body>
</html>"""

    body_parts = [html_head]
    i = 0
    for mod_name, res in results.items():
        i += 1
        vuln = bool(isinstance(res, dict) and res.get("detected", False))
        safe_class = "vuln" if vuln else "safe"
        summary = f"<strong>{escape(mod_name)}</strong> — " + ("⚠️ Vulnerable" if vuln else "✅ No issues")
        pretty = json.dumps(res, ensure_ascii=False, indent=2)
        card = f"""
<div class="card" data-vuln="{str(vuln).lower()}">
  <div class="card-header">
    <span class="module">{escape(mod_name)}</span>
    <span class="status {safe_class}">{'VULN' if vuln else 'OK'}</span>
    <button onclick="toggle('body{i}')">展开/折叠</button>
    <button onclick="copyText('pre{i}')">复制JSON</button>
  </div>
  <div id="body{i}" class="card-body" style="display:none">
    <pre id="pre{i}">{escape(pretty)}</pre>
  </div>
</div>
"""
        body_parts.append(card)
    body_parts.append(html_tail)
    html_doc = "".join(body_parts)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
