const { exec } = require("node:child_process");
exports.list = (dir) => exec("ls " + dir);
