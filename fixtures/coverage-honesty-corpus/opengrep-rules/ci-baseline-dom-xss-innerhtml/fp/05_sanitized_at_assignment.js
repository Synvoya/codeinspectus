// Re-triage 2: the value is sanitised, escaped, encoded or reduced to a boolean where it is assigned.
const el = document.getElementById("out");
const safe = DOMPurify.sanitize(location.hash);
el.innerHTML = safe;
const params = new URLSearchParams(location.search);
const cleaned = DOMPurify.sanitize(params.get("q"));
el.innerHTML = cleaned;
const sp = new URLSearchParams(window.location.search);
const name = escapeHtml(sp.get("name"));
el.innerHTML = `Hello ${name}`;
const encoded = encodeURIComponent(sp.get("next"));
el.innerHTML = `<a href="/u?n=${encoded}">x</a>`;
const isMenu = location.hash === "#menu";
el.innerHTML = isMenu ? "<b>menu</b>" : "";
const h = location.hash;
const open = h !== "#closed";
el.innerHTML = open ? "<b>open</b>" : "";
