// Route parameters are always strings, so they cannot carry an operator object.
const User = require("./models/user");
module.exports = (req) => User.findOne({ _id: req.params.id });
