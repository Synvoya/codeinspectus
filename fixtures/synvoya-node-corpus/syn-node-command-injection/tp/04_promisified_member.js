const util = require("util");
const cp = require("child_process");
const execP = util.promisify(cp.exec);
exports.list = async (req, res) => {
  const { stdout } = await execP("ls -la " + req.query.dir);
  res.send(stdout);
};
