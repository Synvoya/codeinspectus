const jwt = require("jsonwebtoken");
module.exports = function auth(token, key) {
  return jwt.verify(token, key, { algorithms: ["RS256"], issuer: "api" });
};
