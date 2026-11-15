const crypto = require("node:crypto");

export const digest = (password, salt) => crypto.scryptSync(password, salt, 32).toString("hex");
