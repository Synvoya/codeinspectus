import fs from "fs";
// Known gap: the rule only matches when request input starts the path.
export function h(req: any) {
  return fs.readFileSync("/srv/files/" + req.query.name);
}
