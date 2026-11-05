export function greet(el: HTMLElement): void {
  const name = new URLSearchParams(window.location.search).get("name");
  el.insertAdjacentHTML("beforeend", `<b>Hello ${name}</b>`);
}
