/**
 * @name Hardcoded string assigned to a secret-looking name
 * @description Assigning a non-empty string literal to a variable or attribute
 *              whose name matches password/secret/token/api_key strongly
 *              suggests a hardcoded credential (CWE-798).
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id py/demo/hardcoded-secret-name
 * @tags security
 *       demo
 *       external/cwe/cwe-798
 */

// Third query pattern: match assignments where the target *name* looks
// sensitive and the value is a non-trivial string literal. Handles two
// shapes at once by union'ing over Name and Attribute targets:
//
//   DB_PASSWORD = "hunter2"                 # target is a Name
//   app.secret_key = "super-secret-key-…"   # target is an Attribute
//
// Both of these appear near the top of app.py.

import python

from Assign a, Expr target, StrConst s, string label
where
  target = a.getATarget() and
  s = a.getValue() and
  // Ignore empty or trivially short strings — reduces false positives on
  // placeholder assignments like `password = ""`.
  s.getText().length() > 3 and
  (
    (
      label = target.(Name).getId() and
      label.regexpMatch("(?i).*(password|passwd|secret|token|api[_-]?key).*")
    )
    or
    (
      label = target.(Attribute).getName() and
      label.regexpMatch("(?i).*(password|passwd|secret|token|api[_-]?key).*")
    )
  )
select a, "Hardcoded string assigned to secret-looking name '" + label + "'."
