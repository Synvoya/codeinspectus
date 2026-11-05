const User = require("./models/user");
module.exports = (req) => User.findOne({ email: req.body.email });
