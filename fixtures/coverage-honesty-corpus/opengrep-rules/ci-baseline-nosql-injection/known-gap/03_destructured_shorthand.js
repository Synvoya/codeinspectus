// KNOWN GAP (documented): the value is destructured first and passed as shorthand.
const User = require("./models/user");
exports.login = async (req, res) => {
  const { email } = req.body;
  res.json(await User.findOne({ email }));
};
