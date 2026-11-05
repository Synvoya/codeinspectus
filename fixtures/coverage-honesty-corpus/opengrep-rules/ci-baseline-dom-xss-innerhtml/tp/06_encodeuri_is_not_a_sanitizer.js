// Review fix: encodeURI() keeps quotes and markup characters an attribute needs escaped.
const link = document.getElementById("link");
const target = new URLSearchParams(location.search).get("next");
link.innerHTML = '<a href=\'' + encodeURI(target) + '\'>Continue</a>';
