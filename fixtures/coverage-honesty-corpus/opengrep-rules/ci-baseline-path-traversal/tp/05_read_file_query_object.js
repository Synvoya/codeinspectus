const fs = require("fs");
export function h(req, cb) {
  fs.readFile(req.query + ".json", cb);
}
