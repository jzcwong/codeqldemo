# CodeQL Demo — Vulnerable Flask App

A deliberately-vulnerable mini web app used to demonstrate GitHub CodeQL:
static analysis, taint tracking, PR annotations, and the Security tab.

> ⚠️ **DO NOT DEPLOY.** Every route contains at least one CVE-class bug on purpose.

## What's in the app

`app.py` seeds one vulnerability per route so CodeQL's default query suite has
things to find:

| Route         | Vulnerability             | CWE     | CodeQL query ID                |
|---------------|---------------------------|---------|--------------------------------|
| `/login`      | SQL injection             | CWE-089 | `py/sql-injection`             |
| `/greet`      | Reflected XSS             | CWE-079 | `py/reflective-xss`            |
| `/download`   | Path traversal            | CWE-022 | `py/path-injection`            |
| `/ping`       | OS command injection      | CWE-078 | `py/command-line-injection`    |
| `/load-prefs` | Insecure deserialization  | CWE-502 | `py/unsafe-deserialization`    |
| module scope  | Hardcoded credentials     | CWE-798 | `py/hardcoded-credentials`     |
| `static/app.js` | DOM XSS                 | CWE-079 | `js/xss-through-dom`           |

Plus a Flask `debug=True` finding (`py/flask-debug`) for free.

## Repo layout

```
.
├── .github/workflows/codeql.yml   # CodeQL Action, python + javascript
├── app.py                         # vulnerable Flask app
├── static/app.js                  # vulnerable client JS
├── user_files/                    # served by /download
├── requirements.txt
└── DEMO.md                        # step-by-step walkthrough
```

## Quick start — run the app locally (optional)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
# open http://localhost:5000
```

Exploit examples:
- SQLi:  `curl "http://localhost:5000/login?username=' OR '1'='1"`
- XSS:   `open "http://localhost:5000/greet?name=<script>alert(1)</script>"`
- Path:  `curl "http://localhost:5000/download?filename=../../etc/passwd"`
- RCE:   `curl "http://localhost:5000/ping?host=127.0.0.1;id"`

## Running the demo

See [DEMO.md](./DEMO.md) for the full runbook (push to GitHub, watch CodeQL
find the bugs, open the fix PR, watch the alerts resolve).
