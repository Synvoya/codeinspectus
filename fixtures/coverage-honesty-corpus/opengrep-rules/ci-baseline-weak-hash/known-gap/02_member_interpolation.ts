// KNOWN GAP (documented, both implementations): a template literal interpolating a member expression
// (`${user.password}`). Opengrep 1.33.1 does not match it, so the native rule leaves it out for parity.
import { createHash } from "node:crypto";
export const digest = (user: { name: string; password: string }) => createHash("md5").update(`${user.name}:${user.password}`).digest("hex");
