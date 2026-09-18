/**
 * @name render_template_string called with a non-literal template
 * @description `flask.render_template_string` compiles its first argument as
 *              a Jinja template. If that argument isn't a compile-time string
 *              literal, it was almost certainly built by concatenation or
 *              f-string interpolation — and Jinja's autoescape only escapes
 *              *values* passed to the template context, not markup pasted
 *              into the template itself. The result is XSS or full server-
 *              side template injection.
 *
 *              This is a stricter, easier-to-audit sibling of the built-in
 *              `py/reflective-xss`: instead of tracking a taint path from a
 *              request source to a sink, we ban the dangerous shape outright.
 *              Every non-literal render_template_string is worth a code
 *              review, even if today's flow happens to be safe.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id py/demo/template-string-nonliteral
 * @tags security
 *       demo
 *       demo-project-rule
 *       external/cwe/cwe-079
 *       external/cwe/cwe-1336
 */

import python

// Matches calls to `render_template_string(...)`. We match by callee name
// rather than fully-qualified module path — good enough for the demo. A
// production query would use the API graph:
//   API::moduleImport("flask").getMember("render_template_string").getACall()
// which resolves through aliases and `from flask import ...` correctly.

from Call call, Expr arg
where
  call.getFunc().(Name).getId() = "render_template_string" and
  arg = call.getArg(0) and
  // The safe shape is a single string literal — everything else is suspect.
  // Common bad shapes this catches:
  //   render_template_string("<h1>Hi " + name + "</h1>")    -- BinaryExpr
  //   render_template_string(f"<h1>Hi {name}</h1>")         -- Fstring
  //   template = "<h1>Hi " + name + "</h1>"                 -- Name (var
  //   render_template_string(template)                        holding concat)
  not arg instanceof StrConst
select call,
  "render_template_string called with a non-literal template — Jinja autoescape does not cover markup built by string operations."
