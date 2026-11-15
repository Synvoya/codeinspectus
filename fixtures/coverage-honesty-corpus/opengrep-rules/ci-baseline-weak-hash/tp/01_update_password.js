const crypto = require("crypto");
module.exports = (password) => crypto.createHash("md5").update(password).digest("hex");
