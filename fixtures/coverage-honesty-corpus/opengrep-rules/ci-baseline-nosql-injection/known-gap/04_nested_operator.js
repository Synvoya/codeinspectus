// KNOWN GAP (documented): the request value sits inside a nested operator object.
const User = require("./models/user");
exports.older = async (req, res) => {
  res.json(await User.find({ age: { $gt: req.query.age } }));
};
