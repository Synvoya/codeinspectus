export function render(el: HTMLElement): void {
  const url = new URL(window.location.href);
  const next = url.searchParams.get("next");
  el.innerHTML = `<a href="${next}">Continue</a>`;
}
