const crypto = require("crypto");
module.exports = (key, iv) => crypto.createCipheriv("des", key, iv);
