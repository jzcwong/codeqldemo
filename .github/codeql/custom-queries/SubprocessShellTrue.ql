/**
 * @name subprocess call with shell=True
 * @description Passing `shell=True` to subprocess makes /bin/sh parse the
 *              command string, so any user-controlled substring can inject
 *              extra shell commands (CWE-078).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id py/demo/subprocess-shell-true
 * @tags security
 *       demo
 *       external/cwe/cwe-078
 */

// This query is a step up from FlaskDebugTrue.ql: instead of matching a single
// method name, we match a *set* of subprocess entry points. It fires on the
// /ping route in app.py which uses subprocess.check_output(..., shell=True).
//
// Note: unlike the built-in `py/command-line-injection` query, this one does
// NOT taint-track — it flags every shell=True call, even ones with hardcoded
// commands. That's the trade-off of a simple AST-level query: less precise,
// but easier to write and audit.

import python

from Call call, Keyword kw, string funcName
where
  funcName = call.getFunc().(Attribute).getName() and
  funcName in ["check_output", "check_call", "call", "run", "Popen"] and
  kw = call.getAKeyword() and
  kw.getArg() = "shell" and
  kw.getValue().toString() = "True"
select call,
  "subprocess." + funcName + "(..., shell=True) — command injection risk if any argument is attacker-controlled."
