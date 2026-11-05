import jwt from "jsonwebtoken";
export function expiry(stored: string): number {
  const payload: any = jwt.decode(stored);
  return payload.exp;
}
