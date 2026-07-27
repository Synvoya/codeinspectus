import crypto from "node:crypto";

export const cipher = crypto.createCipheriv("chacha20-poly1305", key, iv);
