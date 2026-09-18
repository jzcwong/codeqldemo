/**
 * @name Flask route handler missing an authentication decorator
 * @description Every request handler registered with `@app.route` (or a
 *              blueprint `.route`) should also carry an authentication
 *              decorator such as `@login_required`. Handlers without one are
 *              reachable by unauthenticated requests. Enforcing this as a
 *              lint-level rule catches the class before deploy — the built-in
 *              CodeQL suites can't, because "which decorator counts as auth"
 *              is a project convention, not a language feature.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id py/demo/route-missing-auth
 * @tags security
 *       demo
 *       demo-project-rule
 *       external/cwe/cwe-306
 */

// This is the "custom QL earns its keep" example: a project-specific rule
// that the built-in suites cannot express. We encode two predicates —
// "is a route decorator" and "is an auth decorator" — and flag any function
// that has the first without the second.

import python

// Matches `@app.route("/foo")` and `@some_bp.route("/foo")`. A decorator is
// a Call whose callee is `.route`.
predicate isRouteDecorator(Expr d) {
  d.(Call).getFunc().(Attribute).getName() = "route"
}

// Matches any decorator whose *name* looks like an auth check. Add your
// project's real decorator names to this regex — that's the tuning knob.
predicate isAuthDecorator(Expr d) {
  exists(string name |
    (
      // @login_required
      name = d.(Name).getId()
      or
      // @auth.login_required
      name = d.(Attribute).getName()
      or
      // @login_required()
      name = d.(Call).getFunc().(Name).getId()
      or
      // @auth.login_required()
      name = d.(Call).getFunc().(Attribute).getName()
    ) and
    name.regexpMatch("(?i).*(login_required|requires?_auth|authenticated|auth_required|require_login).*")
  )
}

from Function f
where
  isRouteDecorator(f.getADecorator()) and
  not exists(Expr auth | auth = f.getADecorator() and isAuthDecorator(auth))
select f,
  "Route handler '" + f.getName() +
  "' has no authentication decorator — anyone who can reach the port can invoke it."
