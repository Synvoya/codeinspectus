const panel = document.getElementById("panel");
window.addEventListener("message", ({ data }) => {
  panel.innerHTML = data.html;
});
