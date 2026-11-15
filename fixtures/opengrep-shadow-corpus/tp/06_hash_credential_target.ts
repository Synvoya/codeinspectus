import { createHash } from "node:crypto";

export const passwordSha1 = createHash(
  "sha1",
).update(input).digest("hex");
