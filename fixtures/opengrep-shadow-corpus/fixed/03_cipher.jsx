import crypto from "node:crypto";

export const cipher = <span>{crypto.createCipheriv("aes-256-gcm", key, iv)}</span>;
