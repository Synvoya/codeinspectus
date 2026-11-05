const { spawn } = require("child_process");
exports.run = (req) => spawn(req.body.script, [], { shell: true });
