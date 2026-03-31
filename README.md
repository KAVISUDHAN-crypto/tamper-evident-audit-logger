# tamper-evident-audit-logger
## How to clone and run this project

1. Create a project folder and a virtual environment:

```bash
mkdir tamper_log_assignment
cd tamper_log_assignment
python3 -m venv venv
source venv/bin/activate
```

2. Clone the repository **inside** this folder (or inside `venv`, if you prefer):

```bash
git clone https://github.com/KAVISUDHAN-crypto/tamper-evident-audit-logger.git
```

This will create a sub‑folder `tamper-evident-audit-logger` inside your current directory.

3. Move into the cloned repo:

```bash
cd tamper-evident-audit-logger
```

4. Install Flask (for the browser UI):

```bash
pip install flask
```

5. Run the CLI demo:

```bash
python3 demo.py
```

6. Run the desktop GUI:

```bash
python3 gui.py
```

7. Run the web UI:

```bash
python3 web_app.py
```

Then open your browser and go to:

```text
http://127.0.0.1:5000
```
