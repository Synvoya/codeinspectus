const panel = document.getElementById("panel");
window.addEventListener("message", function (ev) {
  const msg = ev.data;
  panel.innerHTML = msg.html;
});
