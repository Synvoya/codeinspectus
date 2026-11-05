const fs = require("fs");
const path = require("path");
export function h(req, cb) {
  fs.readFile(path.join("/srv", req.params.f) + ".txt", cb);
}
