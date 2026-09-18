# Custom CodeQL queries

This directory holds a **CodeQL query pack** with a small set of hand-written
queries and a suite that runs them. It's wired into `.github/workflows/codeql.yml`
alongside the standard `security-and-quality` suite.

## Anatomy

```
custom-queries/
├── qlpack.yml            # pack manifest: name, version, language dependency
├── custom-suite.qls      # query suite — the "what to run" YAML
├── FlaskDebugTrue.ql     # single query: AST match for app.run(debug=True)
├── SubprocessShellTrue.ql# single query: AST match for subprocess.*(shell=True)
└── HardcodedSecretName.ql# single query: string literals assigned to secret-ish names
```

### `qlpack.yml`

A CodeQL **pack** groups queries with the library versions they need. This
one is not a library (`library: false`) and depends on the Python standard
library pack `codeql/python-all`. For JavaScript you'd use `codeql/javascript-all`.

### `.ql` — a single query

Every query has three parts:

1. **Metadata comment** — `@name`, `@id`, `@kind`, `@problem.severity`,
   `@security-severity`, `@precision`, `@tags`. GitHub uses these to render
   the alert in the Security tab and to map to CWEs. `@id` must be unique
   and typically follows `<language>/<slug>` (we use `py/demo/...`).
2. **`import`** — pulls in the language's standard CodeQL library.
3. **`from … where … select …`** — a logic-programming query over program
   facts. `select` produces one row per finding: `select <location>, "<message>"`.

Two useful "kinds":

- `@kind problem` — a single-location alert (all three queries here).
- `@kind path-problem` — a source-to-sink data-flow alert; requires more
  library scaffolding (`import DataFlow::PathGraph`, a `Configuration`
  class, and `select sink, source, sink, "…"`). The built-in
  `py/sql-injection` query is a path-problem.

### `.qls` — a query suite

A suite is YAML that selects which queries to run. Ours is one line
(`queries: '.'`) meaning "every `.ql` in this pack." Suites can also
filter by tag, precision, or `@id`:

```yaml
- queries: '.'
- include:
    tags contain: security
    precision:
      - high
      - very-high
- exclude:
    id: py/demo/hardcoded-secret-name
```

## How this hooks into GitHub Actions

`.github/workflows/codeql.yml` sets:

```yaml
queries: security-and-quality,./.github/codeql/custom-queries/custom-suite.qls
```

The `queries:` field takes a comma-separated list. Entries can be:

- a named built-in suite (`default`, `security-extended`, `security-and-quality`)
- a path to a `.qls` file
- a path to a directory containing `.ql` files (all get run)
- a published pack reference (`codeql/python-queries@1.2.3`)

For `packs:` (an alternative to `queries:`) see the CodeQL Action docs —
it's the right choice when you want to consume a versioned published pack.

## Running locally

Install the [CodeQL CLI](https://github.com/github/codeql-cli-binaries), then:

```bash
# create a database from this repo (once)
codeql database create db --language=python --source-root=.

# run one query
codeql query run \
  --database=db \
  .github/codeql/custom-queries/FlaskDebugTrue.ql

# run the whole suite as SARIF
codeql database analyze db \
  .github/codeql/custom-queries/custom-suite.qls \
  --format=sarifv2.1.0 --output=results.sarif
```

## Where to go next

- Docs: <https://codeql.github.com/docs/writing-codeql-queries/>
- Standard-library reference: <https://codeql.github.com/codeql-standard-libraries/python/>
- Example queries: browse the [`github/codeql`](https://github.com/github/codeql/tree/main/python/ql/src) repo — every `.ql` under `python/ql/src/Security/` is a real production query you can read and copy patterns from.
