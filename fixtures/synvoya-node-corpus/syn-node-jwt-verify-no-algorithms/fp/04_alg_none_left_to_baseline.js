// Reported by ci-baseline-jwt-alg-none (its tp/02 and tp/03); never by this rule.
const jwt = require("jsonwebtoken");
module.exports = (token, key) => jwt.verify(token, key, { algorithm: "none" });
