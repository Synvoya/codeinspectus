const fs = require("fs");
export function h(req, cb) {
  fs.readFile(req.params + ".json", cb);
}
