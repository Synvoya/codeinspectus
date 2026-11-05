import { verify } from "jsonwebtoken";
export const check = (token: string, key: string) => verify(token, key, { algorithm: "none" });
