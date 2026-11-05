const jwt = require("jsonwebtoken");
module.exports = function currentUser(req, res, next) {
  const token = req.headers.authorization.split(" ")[1];
  jwt.verify(token, process.env.KEY, { algorithms: ["HS256"] });
  const claims = jwt.decode(token, { complete: true });
  req.kid = claims.header.kid;
  next();
};
