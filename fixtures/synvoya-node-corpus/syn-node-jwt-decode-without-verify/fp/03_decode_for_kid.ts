import jwt from "jsonwebtoken";
export async function authenticate(req: any, keys: Map<string, string>) {
  const token = req.headers.authorization.slice(7);
  const decoded: any = jwt.decode(token, { complete: true });
  const key = keys.get(decoded.header.kid) as string;
  const claims = jwt.verify(token, key, { algorithms: ["RS256"] });
  return claims;
}
