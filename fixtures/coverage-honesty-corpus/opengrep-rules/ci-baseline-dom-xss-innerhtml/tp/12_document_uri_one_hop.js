// Security review: documentURI and baseURI are full-URL sources through a variable too.
const where = document.documentURI;
document.getElementById("a").innerHTML = "<p>" + where + "</p>";
const base = document.baseURI;
document.getElementById("b").innerHTML = "<p>" + base + "</p>";
