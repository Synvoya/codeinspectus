import { createHash } from "node:crypto";
export const basicDigest = (user: string, password: string) => createHash("sha1").update(`${user}:${password}`).digest("hex");
