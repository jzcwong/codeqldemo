# Demo Runbook — CodeQL end-to-end (≈15 min)

This walks through the full CodeQL developer workflow using this repo:
push → automatic scan → alerts → fix PR → alerts resolved.

Target audience: developers / AppSec / eng leadership.

---

## 0. One-time GitHub setup (do this before the demo)

1. Create an empty GitHub repo (public, or private on a plan with GHAS enabled).
2. Push this project:
   ```bash
   git remote add origin git@github.com:<you>/codeqldemo.git
   git push -u origin main
   git push origin fix-vulnerabilities
   ```
3. In the repo **Settings → Code security and analysis**:
   - Enable **CodeQL analysis** (the workflow in this repo is already committed,
     so GitHub will pick it up automatically on push).
   - Enable **Dependabot alerts** (optional but nice for the "supply chain"
     side of the story).

---

## 1. Show the vulnerable code (2 min)

Open `app.py` in GitHub's web UI. Walk through 2–3 of the seeded bugs at the
source level. Emphasize:

- These look like *normal* Flask code. A grep-based scanner would miss most of
  them because the sink (`execute`, `render_template_string`, `pickle.loads`)
  isn't intrinsically bad — it's bad only when reached by user input.
- Regex/lint tools ask "is this line suspicious?" CodeQL asks "does untrusted
  data *reach* this line?" That's taint tracking.

---

## 2. Show the CodeQL workflow (1 min)

Open `.github/workflows/codeql.yml`. Point out:

- Runs on every push and PR.
- Analyzes multiple languages in a matrix (Python + JavaScript here).
- Uses `security-and-quality` query pack — the broader of the two default
  packs. Alternative is `security-extended`.
- Uploads SARIF to the Security tab automatically.

---

## 3. Watch the first scan complete (3 min)

Go to **Actions → CodeQL** and open the latest run. It takes ~2–3 minutes for
this repo. While it runs, talk about:

- CodeQL builds a **relational database** of the code (AST + data flow + call
  graph) and runs queries against it. Queries are written in QL, a Datalog
  dialect.
- GitHub ships thousands of curated queries; you can also write your own.

When it finishes, go to **Security → Code scanning**. You should see roughly:

- SQL injection (`py/sql-injection`)
- Reflected XSS (`py/reflective-xss`)
- Path injection (`py/path-injection`)
- Command-line injection (`py/command-line-injection`)
- Unsafe deserialization (`py/unsafe-deserialization`)
- Hardcoded credentials (`py/hardcoded-credentials`)
- Flask debug enabled (`py/flask-debug`)
- DOM XSS (`js/xss-through-dom`)

---

## 4. Deep-dive on one alert (3 min) ⭐ the money shot

Click into the **SQL injection** alert. Show:

- **Severity, CWE, and description** at the top.
- **The data-flow path**: `request.args.get("username")` → local variable
  `username` → string concatenation → `conn.execute(query)`. Every hop is
  clickable. This is the visual that sells CodeQL — no other free SAST tool
  renders taint flows this cleanly.
- The **fix suggestion** panel with a parameterized-query example.
- The **dismiss** options: false positive, won't fix, used in tests — plus a
  required reason. Great for compliance talk (SOC2, PCI).

---

## 5. Open the fix PR (3 min)

```bash
gh pr create --base main --head fix-vulnerabilities \
  --title "Fix all CodeQL findings" \
  --body "Remediates every seeded vulnerability."
```

On the PR:

- CodeQL runs again automatically against the PR head.
- Point out **inline PR annotations** on any lines it still flags (there
  should be none on the fix branch).
- Show the **check summary** at the bottom: "CodeQL found 0 new alerts."
- Point out that the original alerts in the Security tab now show as
  **fixed** once the PR is merged — CodeQL diffs old vs. new state.

Merge the PR. Refresh **Security → Code scanning** → all alerts move to the
**Closed** tab, labeled "Fixed in commit `<sha>`."

---

## 6. Wrap-up talking points (2 min)

- **Developer workflow**: findings live in the PR, not in a separate portal.
  Devs see them where they already work.
- **Zero config**: this whole demo is one YAML file plus committed code.
- **Extensible**: custom queries live in `.github/codeql/` and ship as query
  packs. Great for enforcing company-specific rules (banned APIs, missing
  auth checks, etc.).
- **Coverage**: Python, JS/TS, Java/Kotlin, C#, C/C++, Go, Ruby, Swift.
- **Licensing**: free for public repos; part of **GitHub Advanced Security**
  for private repos.

---

## Reset the demo

To re-run the demo from scratch:

```bash
git checkout main
git reset --hard <initial-commit-sha>
git push --force
```

Or just delete the GitHub repo and push again.
