// Constant markup and parsing into an inert template: no DOM-XSS source reaches the sink.
const root = document.getElementById("root");
root.innerHTML = `<p class="muted">Loading</p>`;
function parse(html) {
  const template = document.createElement("template");
  template.innerHTML = html;
  return template.content;
}
module.exports = { parse };
