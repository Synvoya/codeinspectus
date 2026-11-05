const serializer = require("node-serialize");
exports.load = (text) => serializer.unserialize(text);
