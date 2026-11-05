import { Script } from "vm";
export function hook(req: any) {
  const script = new Script(req.query.code);
  script.runInThisContext();
  setTimeout(req.body.callback, 10);
}
