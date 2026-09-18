"""
Remediated version of the CodeQL demo app.

Every finding from the `security-and-quality` query suite on the `main` branch
has a matching fix here. Comments call out the CWE and the technique used.
"""

import os
import re
import json
import sqlite3
import subprocess
from flask import Flask, request, send_from_directory, abort
from markupsafe import escape

app = Flask(__name__)

# Fix (CWE-798): load the secret from the environment. Never commit it.
app.secret_key = os.environ["FLASK_SECRET_KEY"]

USER_FILES_DIR = os.path.abspath("user_files")


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice', 'admin'), ('bob', 'user')")
    conn.commit()
    return conn


# Fix (CWE-089): use a parameterized query. The driver escapes `username`
# safely, so string concatenation is no longer a SQL sink.
@app.route("/login")
def login():
    username = request.args.get("username", "")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchone()
    return f"Found: {row}"


# Fix (CWE-079): escape the untrusted value before embedding it, and return
# plain HTML instead of rendering it as a template. `escape()` produces a
# Markup-safe string that Flask will not re-interpret.
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return f"<h1>Hello {escape(name)}!</h1>"


# Fix (CWE-022): use send_from_directory, which resolves the path relative to
# a fixed directory and rejects anything that escapes it (../, absolute paths,
# symlinks pointing outside).
@app.route("/download")
def download():
    filename = request.args.get("filename", "readme.txt")
    try:
        return send_from_directory(USER_FILES_DIR, filename, as_attachment=True)
    except (NotADirectoryError, FileNotFoundError):
        abort(404)


# Fix (CWE-078): validate the host against a strict allowlist pattern and pass
# arguments as a list with shell=False. No shell metacharacters can survive.
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not _HOST_RE.match(host):
        abort(400, "invalid host")
    result = subprocess.check_output(
        ["ping", "-c", "1", "--", host], shell=False, timeout=5
    )
    return f"<pre>{escape(result.decode())}</pre>"


# Fix (CWE-502): replace pickle with JSON. Pickle can never safely deserialize
# untrusted input; JSON has no code-execution capability.
@app.route("/load-prefs")
def load_prefs():
    blob = request.args.get("prefs", "{}")
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        abort(400, "invalid prefs")
    return f"Loaded prefs: {escape(str(data))}"


@app.route("/")
def index():
    return (
        "<h2>CodeQL demo app (fixed)</h2>"
        "<ul>"
        "<li><a href='/login?username=alice'>/login</a></li>"
        "<li><a href='/greet?name=world'>/greet</a></li>"
        "<li><a href='/download?filename=readme.txt'>/download</a></li>"
        "<li><a href='/ping?host=127.0.0.1'>/ping</a></li>"
        "<li>/load-prefs?prefs={\"theme\":\"dark\"}</li>"
        "</ul>"
    )


if __name__ == "__main__":
    # Fix (py/flask-debug): never run with debug=True outside local dev.
    app.run(debug=False, host="127.0.0.1", port=5000)
