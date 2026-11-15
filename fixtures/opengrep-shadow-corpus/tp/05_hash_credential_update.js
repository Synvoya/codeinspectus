const crypto = require("node:crypto");

export const digest = (password) => crypto.createHash("md5").update(password).digest("hex");
