const cp = require("child_process");
exports.ping = (req, res) => {
  const cmd = "ping -c 1 " + req.query.host;
  cp.exec(cmd, (err, out) => res.send(out));
};
