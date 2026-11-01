const serialize = require("node-serialize");
module.exports = (body) => serialize.unserialize(body);
