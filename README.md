# MiniScanner — 教育用轻量级漏洞检测器

**MiniScanner** 是一个面向课堂与学习用途的轻量级漏洞检测工具（PoC / 教学版），基于 Python 开发，支持模块化插件（目前包含 `sql`、`xss`、`port`、`bruteforce` 等）。项目目标是为课堂演示、渗透测试入门与脚本语言设计课程提供一个可扩展、易读的实战样例，同时支持本地演示靶场（如 DVWA、sqli-labs）。

> 强烈声明：本工具仅用于*合法授权*的测试（你**拥有**或**被授权**测试的目标）。切勿将其用于未经授权的系统或进行非法入侵。使用之前请务必遵守当地法律与组织政策，并遵守负责任披露原则。

---

## 主要特性

- 模块化扫描器：以模块（module）方式组织（`sql`, `xss`, `port`, `bruteforce`），方便扩展。
- 支持 Cookie 登录（DVWA 等需要 Cookie 的本地靶场）。
- 输出 JSON 与 HTML 报告（可直接用于课堂展示）。
- 支持外部 wordlist（`modules/payloads/wordlists/`）用于暴力破解模块。
- 方便打包到 exe（PyInstaller）,目前暂不支持打包为 Docker 镜像（还在开发中）。
- 适合单人或小组课程项目开发、演示与扩展。

---

## 法律与安全（必须阅读）

- 仅对你**有授权**的系统或靶场（如本地 DVWA、sqli-labs）运行本工具。
- 对未授权系统进行扫描/攻击可能构成犯罪或民事责任。使用前请确认权限并保留测试授权凭证。
- 如果在测试中发现真实漏洞，请遵守 **Responsible Disclosure（负责任披露）**，不要公开敏感信息或未经授权泄露漏洞细节。

---

## 快速开始（本地）

1. 克隆仓库
```bash
git clone https://github.com/xyzdol/miniscanner.git
cd miniscanner
2. 创建并激活虚拟环境（Windows / macOS / Linux）
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
3. 安装依赖
```bash
pip install -r requirements.txt
4. 目录结构（简要）
```bash
.
├─ src/                # 主程序（app.py）
├─ modules/            # 各扫描模块（sql_injection.py, xss_scan.py, bruteforce.py, port_scan.py）
│  └─ payloads/
│     └─ wordlists/    # users.txt, passwords.txt
├─ reporters/          # json/html 报告生成器（html_reporter.py, json_reporter.py）
├─ requirements.txt
└─ README.md
