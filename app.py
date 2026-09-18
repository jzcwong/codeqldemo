"""
Intentionally vulnerable Flask app for CodeQL demos.

DO NOT DEPLOY. Every route below contains at least one CWE seeded on purpose
so CodeQL's default `security-and-quality` query suite has something to find.

Vulnerabilities seeded (mapped to CWE + CodeQL query ID):
  - /login          SQL injection            CWE-089  py/sql-injection
  - /greet          Reflected XSS            CWE-079  py/reflective-xss
  - /download       Path traversal           CWE-022  py/path-injection
  - /ping           Command injection        CWE-078  py/command-line-injection
  - /load-prefs     Insecure deserialization CWE-502  py/unsafe-deserialization
  - module scope    Hardcoded secret         CWE-798  py/hardcoded-credentials
"""

import os
import pickle
import base64
import sqlite3
import subprocess
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CWE-798: Hardcoded credentials. CodeQL flags string literals that look like
# secrets assigned to obviously-sensitive names.
# ---------------------------------------------------------------------------
app.secret_key = "super-secret-key-do-not-share-123"
DB_PASSWORD = "hunter2"  # noqa: used by nothing, but CodeQL will still notice


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice', 'admin'), ('bob', 'user')")
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# CWE-089: SQL injection.
# User-controlled `username` is concatenated straight into the SQL string.
# CodeQL taint-tracks request.args -> execute() and reports the full path.
# ---------------------------------------------------------------------------
@app.route("/login")
def login():
    username = request.args.get("username", "")
    conn = get_db()
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    row = conn.execute(query).fetchone()
    return f"Found: {row}"


# ---------------------------------------------------------------------------
# CWE-079: Reflected XSS.
# `name` is rendered inside a template string without escaping. Using
# render_template_string with a format-substituted value bypasses Jinja
# autoescaping entirely.
# ---------------------------------------------------------------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    template = "<h1>Hello " + name + "!</h1>"
    return render_template_string(template)


# ---------------------------------------------------------------------------
# CWE-022: Path traversal.
# `filename` flows into open()/send_file with no normalization, so
# ?filename=../../etc/passwd reads outside the intended directory.
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    filename = request.args.get("filename", "readme.txt")
    path = os.path.join("user_files", filename)
    return send_file(path)


# ---------------------------------------------------------------------------
# CWE-078: OS command injection.
# `host` is interpolated into a shell string passed to subprocess with
# shell=True. `?host=8.8.8.8; rm -rf /` gets executed by /bin/sh.
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return f"<pre>{result.decode()}</pre>"


# ---------------------------------------------------------------------------
# CWE-502: Insecure deserialization.
# pickle.loads on attacker-controlled bytes gives RCE. CodeQL flags any
# tainted flow into pickle.loads / pickle.load.
# ---------------------------------------------------------------------------
@app.route("/load-prefs")
def load_prefs():
    blob = request.args.get("prefs", "")
    data = pickle.loads(base64.b64decode(blob))
    return f"Loaded prefs: {data}"


@app.route("/")
def index():
    return (
        "<h2>CodeQL demo app</h2>"
        "<ul>"
        "<li><a href='/login?username=alice'>/login</a></li>"
        "<li><a href='/greet?name=world'>/greet</a></li>"
        "<li><a href='/download?filename=readme.txt'>/download</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>/ping</a></li>"
        "<li>/load-prefs?prefs=&lt;base64 pickle&gt;</li>"
        "</ul>"
    )


if __name__ == "__main__":
    # debug=True in production is itself a CodeQL finding (py/flask-debug).
    app.run(debug=True, host="0.0.0.0", port=5000)
