// Small client-side helper. Contains one deliberate DOM XSS sink so the
// JavaScript CodeQL analyzer also has something to flag (js/xss-through-dom).

function showGreeting() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") || "friend";

  // CWE-079: user-controlled value written straight into innerHTML.
  // CodeQL taint-tracks location.search -> innerHTML.
  document.getElementById("greeting").innerHTML = "Hello " + name + "!";
}

document.addEventListener("DOMContentLoaded", showGreeting);
