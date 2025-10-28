# Next Steps (Detailed)

1) Git + Local setup
   - Create a repo: `git init` -> commit -> create GitHub repo -> push.
   - Create a branch `dev`.

2) Virtualenv and dependency management
   - `python -m venv .venv`
   - `source .venv/bin/activate` (or `.venv\\Scripts\\activate` on Windows)
   - `pip install -r requirements.txt` (fill the file first)

3) Implement minimal runnable app (CLI)
   - Edit `src/app.py`: parse args for `--target` and `--modules`, import modules, run stub scans.

4) Implement module interface
   - Each module should expose `def scan(target: str) -> dict` returning a small result dict.

5) Add basic tests
   - Use pytest and add smoke tests for module interfaces.

6) Dockerize and Compose
   - Build image and run; test container logging.

7) Prepare demo deliverables
   - PPT: 6-8 slides (Objective, Architecture, Demo steps, Limitations, Q&A)
   - EXE: optional backup demo build using PyInstaller

