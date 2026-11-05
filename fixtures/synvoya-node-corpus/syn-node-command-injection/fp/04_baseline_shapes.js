// Reported by ci-baseline-command-injection (see its tp/04_require_alias.js); never by this rule.
const { exec: run } = require("child_process");
exports.list = (req) => run("ls " + req.query.dir);
