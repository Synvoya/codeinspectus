import { createHash, createCipheriv } from "node:crypto";

export const dynamicHash = createHash(process.env.HASH_ALGORITHM);
export const dynamicCipher = createCipheriv(algorithm, key, iv);
export const caseVariant = createHash("SHA1");
