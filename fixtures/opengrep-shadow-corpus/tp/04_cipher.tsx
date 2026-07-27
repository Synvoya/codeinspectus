import crypto from "node:crypto";

export const rc4 = crypto.createCipheriv(
  "rc4",
  key,
  iv,
);
export const passwordCipher = crypto.createCipher("aes-256-cbc", password);
