const { unserialize } = require("node-serialize");
exports.load = (text) => unserialize(text);
