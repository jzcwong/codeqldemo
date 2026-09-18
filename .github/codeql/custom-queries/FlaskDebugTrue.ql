/**
 * @name Flask application launched with debug=True
 * @description Flask's debug mode enables the Werkzeug interactive debugger,
 *              which allows arbitrary code execution to anyone who can reach
 *              the port. Never enable it in code that ships.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/demo/flask-debug-true
 * @tags security
 *       demo
 *       external/cwe/cwe-489
 */

// A CodeQL query has three parts:
//   1. Metadata comment above (name, kind, id, tags…). GitHub uses this to
//      render results in the Security tab.
//   2. `import` lines that pull in the standard library for the target language.
//   3. A `from … where … select …` clause — SQL-like, over program facts.
//
// This query walks every Call in the program and keeps the ones that:
//   - call something named `.run(...)` on any object (e.g. `app.run(...)`), AND
//   - pass a keyword argument `debug=True`.
//
// It will fire on `app.py:120`: `app.run(debug=True, host="0.0.0.0", port=5000)`.

import python

from Call call, Keyword kw
where
  call.getFunc().(Attribute).getName() = "run" and
  kw = call.getAKeyword() and
  kw.getArg() = "debug" and
  // Match the literal `True`. Using toString() keeps this working across
  // CodeQL library versions that model booleans differently (Name vs
  // BooleanLiteral).
  kw.getValue().toString() = "True"
select call, "Flask app started with debug=True — enables the Werkzeug debugger."
