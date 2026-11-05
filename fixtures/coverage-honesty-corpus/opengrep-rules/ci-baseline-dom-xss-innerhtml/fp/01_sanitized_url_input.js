// URL input that passes a sanitizer or an escaping helper before the sink.
const el = document.getElementById("out");
el.innerHTML = DOMPurify.sanitize(location.hash.slice(1));
const q = new URLSearchParams(location.search).get("q");
el.innerHTML = escapeHtml(q);
el.innerHTML = `<p>${he.encode(q)}</p>`;
