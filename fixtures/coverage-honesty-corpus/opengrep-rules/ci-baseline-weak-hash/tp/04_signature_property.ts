import { createHash } from "node:crypto";
export function sign(payload: string, secret: string) {
  return { signature: createHash("sha1").update(payload + secret).digest("hex") };
}
