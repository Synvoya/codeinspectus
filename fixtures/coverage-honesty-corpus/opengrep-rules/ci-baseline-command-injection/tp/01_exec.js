const cp = require("child_process");
module.exports = (dir) => cp.exec("ls " + dir);
