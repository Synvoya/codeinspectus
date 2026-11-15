// Security review: a request value in the filter is an injection whatever the second argument (here a
// projection taken from the query string) is.
const User = require("./models/user");
exports.lookup = async (req, res) => {
  res.json(await User.findOne({ email: req.body.email }, req.query.fields));
};
exports.list = async (req, res) => {
  // The same source as filter value and as projection object.
  res.json(await User.find({ name: req.query.name }, req.query));
};
