// The two-hop value passes a named HTML sanitizer before the sink.
const params = new URLSearchParams(location.search);
const q = params.get("q");
document.getElementById("out").innerHTML = DOMPurify.sanitize(q);
