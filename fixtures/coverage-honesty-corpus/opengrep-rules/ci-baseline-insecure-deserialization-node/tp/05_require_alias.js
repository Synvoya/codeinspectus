const { unserialize: revive } = require("node-serialize");
exports.load = (text) => revive(text);
