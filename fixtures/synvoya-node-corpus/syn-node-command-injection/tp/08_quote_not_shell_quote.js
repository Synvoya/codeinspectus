const { exec } = require("child_process");
const { quote } = require("./format");
exports.grep = (req, res) => {
  const command = "grep -r " + quote(req.query.term) + " /srv/docs";
  exec(command, (e, out) => res.send(out));
};
