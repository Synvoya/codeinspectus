const box = document.querySelector("#box");
window.addEventListener("message", (event) => {
  box.innerHTML = event.data;
});
