import jwt from "jsonwebtoken";
import { verify } from "jsonwebtoken";
export function check(token: string, key: string) {
  const a = jwt.verify(token, key, { issuer: "api" });
  verify(token, key, (err: any, decoded: any) => decoded);
  return a;
}
