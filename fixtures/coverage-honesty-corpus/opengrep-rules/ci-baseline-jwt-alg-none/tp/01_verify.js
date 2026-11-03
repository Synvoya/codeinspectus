const jwt = require("jsonwebtoken");
module.exports = (token, key) => jwt.verify(token, key, { algorithms: ["none"] });
