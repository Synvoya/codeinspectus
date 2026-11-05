import jwt from "jsonwebtoken";
export function role(req: any): string {
  const payload: any = jwt.decode(req.cookies.session);
  return payload.role;
}
