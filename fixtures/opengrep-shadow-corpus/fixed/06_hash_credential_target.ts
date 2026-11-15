import { scryptSync } from "node:crypto";

export const passwordKey = scryptSync(
  input,
  salt,
  32,
).toString("hex");
