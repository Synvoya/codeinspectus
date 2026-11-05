// Security review: a sanitised assignment followed by a tainted reassignment still reaches the sink.
const el = document.getElementById("out");
let v = DOMPurify.sanitize(window.initial);
v = location.hash;
el.innerHTML = v;
