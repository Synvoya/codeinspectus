import crypto, { createHash } from "node:crypto";
export function keys(url: string, body: string, footprint: string, bypass: string, password: string) {
  const cacheKey = crypto.createHash("md5").update(url).digest("hex");
  const headers = { etag: createHash("sha1").update(body).digest("base64") };
  const footprintHash = crypto.createHash("md5").update(footprint).digest("hex");
  const bypassId = createHash("sha1").update(bypass).digest("hex");
  const strong = crypto.createHash("sha256").update(password).digest("hex");
  return { cacheKey, headers, footprintHash, bypassId, strong };
}
