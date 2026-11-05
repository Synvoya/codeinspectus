const { exec: run } = require("child_process");
exports.list = (dir) => run("ls " + dir);
