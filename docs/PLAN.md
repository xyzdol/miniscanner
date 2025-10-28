# Project Plan — Mini Vulnerability Scanner (Empty Shell)

## Project Goal
Build a lightweight, educational vulnerability scanner (Python) suitable for classroom demonstration and GitHub release.  
The scanner detects common vulnerability categories (SQLi, XSS, simple port checks) with clear limitations documented.

## Milestones
1. Project setup (this empty shell). Create Git repo, CI skeleton, and docs. (DONE)
2. Minimal runnable app: a CLI or FastAPI app that can load modules and run a "scan" on a target.
3. Module scaffolding: implement basic skeletons for sql_injection, xss_scan, port_scan with well-documented interfaces.
4. UI & Reporting: simple HTML UI (Jinja2 + Bootstrap) and result export (TXT/JSON).
5. Dockerize: Dockerfile + docker-compose to run scanner + DVWA for demo.
6. Packaging: PyInstaller script to build an EXE for Windows demo (backup).
7. Tests & Docs: add basic tests, README, and classroom slides.

## Roles / Tasks (single-developer friendly)
- Developer: implements code, tests, builds, docs.
- QA (you can self-test): run scanner against local DVWA.
- Release: prepare GitHub Release and DockerHub image.

## Constraints & Ethics
- Run scans only on authorized targets (e.g., local DVWA).
- This project is educational; detection logic will be intentionally simple.

## Next-step Checklist (pick one to start)
- [ ] Initialize Git repository and push this shell to GitHub.
- [ ] Create virtual environment and install `requirements.txt`.
- [ ] Implement a minimal `src/app.py` CLI that imports a module and prints a mock result.
- [ ] Implement a minimal FastAPI app skeleton if you prefer web UI.
- [ ] Scaffold `modules/sql_injection.py` with a `scan(target)` function stub.
- [ ] Create `templates/index.html` UI basic form for a target and modules selection.
- [ ] Docker test: try `docker build .` and `docker-compose up --build` to verify placeholder runs.

Pick one next-step and I will walk you through it step-by-step.
