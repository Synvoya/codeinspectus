// The page's own host name is not attacker-controlled (field: cap-collectif browserUpdate.ts:312).
const banner = document.getElementById("banner");
const updateUrl = `//browser-update.example/update.html#${location.hostname || "x"}`;
banner.innerHTML = `<a href="${updateUrl}">Update your browser</a>`;
