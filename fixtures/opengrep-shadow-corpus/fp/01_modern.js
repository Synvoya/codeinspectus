const crypto = require("node:crypto");

export const hash = crypto.createHash("sha256");
export const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
