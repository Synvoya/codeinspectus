const { exec: run } = require("child_process");
exports.list = (req, res) => {
  const command = "ls " + req.query.dir;
  run(command, (err, out) => res.send(out));
};
