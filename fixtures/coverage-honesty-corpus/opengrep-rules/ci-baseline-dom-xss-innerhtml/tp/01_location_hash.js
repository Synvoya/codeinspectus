const out = document.getElementById("out");
out.innerHTML = decodeURIComponent(location.hash.slice(1));
