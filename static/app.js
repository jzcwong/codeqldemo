// Fixed version: write user-controlled data as text, not as HTML.
// textContent never parses its argument as markup, so no XSS sink exists.

function showGreeting() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") || "friend";

  document.getElementById("greeting").textContent = "Hello " + name + "!";
}

document.addEventListener("DOMContentLoaded", showGreeting);
