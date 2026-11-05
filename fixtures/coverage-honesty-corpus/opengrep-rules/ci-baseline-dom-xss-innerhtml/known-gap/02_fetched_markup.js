// Known gap: markup fetched from the server (stored XSS) is not a DOM-XSS source for this rule.
module.exports = (el) => fetch("/fragment").then((r) => r.text()).then((html) => {
  el.innerHTML = html;
});
