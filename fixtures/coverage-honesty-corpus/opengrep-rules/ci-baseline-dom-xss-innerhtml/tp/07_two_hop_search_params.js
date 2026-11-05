const params = new URLSearchParams(location.search);
const q = params.get("q");
document.getElementById("out").innerHTML = "<b>" + q + "</b>";
