const jwt = require("jsonwebtoken");
module.exports = function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  req.user = jwt.verify(token, process.env.JWT_PUBLIC_KEY);
  next();
};
