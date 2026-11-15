// Only the projection comes from the request; the filter is server-side data, so no operator can reach it.
const User = require("./models/user");
exports.me = async (req, res) => {
  res.json(await User.findOne({ _id: req.user.id }, req.query.fields));
};
