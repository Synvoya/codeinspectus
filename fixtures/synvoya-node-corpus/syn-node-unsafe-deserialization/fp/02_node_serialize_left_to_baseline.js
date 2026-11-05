// node-serialize is reported by ci-baseline-insecure-deserialization-node, never by this rule.
const { unserialize } = require("node-serialize");
exports.profile = (req) => unserialize(req.cookies.profile);
exports.inline = (text) => require("node-serialize").unserialize(text);
