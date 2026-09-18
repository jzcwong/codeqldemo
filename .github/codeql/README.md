# Custom CodeQL queries

This directory holds a **CodeQL query pack** with a small set of hand-written
queries and a suite that runs them. It's wired into `.github/workflows/codeql.yml`
alongside the standard `security-and-quality` suite.

## Why write custom queries at all?

The built-in `security-and-quality` suite already catches most of what's in
this repo. Custom QL earns its place when you need one of four things the
built-ins can't give you:

1. **Project-specific rules** — conventions the language doesn't know about,
   like "every route must be wrapped with `@login_required`."
2. **Different precision/recall trade-offs** — e.g. flag *every* `shell=True`,
   even ones the built-in taint tracker deems unreachable.
3. **Custom sinks/sources** for the built-in taint library — internal SDKs
   the shipped library doesn't model.
4. **New AST-level anti-patterns** the built-ins don't cover.

Two of the three queries here are chosen specifically to *not* overlap with
built-ins so you can see the value:

| File | Category | Overlaps with built-in? |
|---|---|---|
| `RouteMissingAuth.ql` | Project-specific rule (#1) | **No** — auth conventions are project-defined. |
| `TemplateStringNonLiteral.ql` | AST anti-pattern (#4) | Partial — `py/reflective-xss` needs a taint path; this bans the shape. |
| `SubprocessShellTrue.ql` | Precision trade-off (#2) | Yes, with `py/command-line-injection` — this one is intentionally louder. |

## Anatomy

```
custom-queries/
├── qlpack.yml                    # pack manifest: name, version, language dependency
├── custom-suite.qls              # query suite — the "what to run" YAML
├── RouteMissingAuth.ql           # project-rule: @app.route without an auth decorator
├── TemplateStringNonLiteral.ql   # anti-pattern: render_template_string(<non-literal>)
└── SubprocessShellTrue.ql        # AST match for subprocess.*(shell=True)
```

Each `.ql` file's header comment explains what it fires on and where in
`app.py` you should expect the alerts.

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
  `py/sql-injection` query is a path-problem. If you wanted an even
  stricter version of `TemplateStringNonLiteral.ql` that only fires when
  request data actually reaches the template, you'd rewrite it as a
  `path-problem` with `RemoteFlowSource` as the source and the
  `render_template_string` argument as the sink.

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
    id: py/demo/subprocess-shell-true
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
  .github/codeql/custom-queries/RouteMissingAuth.ql

# run the whole suite as SARIF
codeql database analyze db \
  .github/codeql/custom-queries/custom-suite.qls \
  --format=sarifv2.1.0 --output=results.sarif
```

## Where to go next

- Docs: <https://codeql.github.com/docs/writing-codeql-queries/>
- Standard-library reference: <https://codeql.github.com/codeql-standard-libraries/python/>
- Example queries: browse the [`github/codeql`](https://github.com/github/codeql/tree/main/python/ql/src) repo — every `.ql` under `python/ql/src/Security/` is a real production query you can read and copy patterns from.
