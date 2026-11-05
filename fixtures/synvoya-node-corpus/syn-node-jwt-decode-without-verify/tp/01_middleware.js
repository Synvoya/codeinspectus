const jwt = require("jsonwebtoken");
module.exports = function currentUser(req, res, next) {
  const token = req.headers.authorization.split(" ")[1];
  const claims = jwt.decode(token);
  req.userId = claims.sub;
  next();
};
