// Review fix: unescape() decodes, it does not sanitize; the URL fragment still reaches the sink.
const out = document.getElementById("out");
out.innerHTML = unescape(location.hash.slice(1));
