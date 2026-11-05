const jwt = require("jsonwebtoken");
module.exports = (token, key) => jwt.verify(token, key, { algorithm: "none" });
