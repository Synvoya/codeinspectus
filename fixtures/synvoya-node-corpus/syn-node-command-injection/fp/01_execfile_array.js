const { execFile, spawn } = require("child_process");
exports.ping = (req, res) => {
  execFile("ping", ["-c", "1", req.query.host], (err, out) => res.send(out));
  spawn("ls", ["-la", req.query.dir]);
};
