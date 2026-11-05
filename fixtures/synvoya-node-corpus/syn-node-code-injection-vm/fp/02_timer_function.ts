export function later(req: any, run: () => void) {
  setTimeout(function () { run(); }, req.query.wait);
  setInterval(run, 1000);
}
