import jwt from "jsonwebtoken";
export const decodeForTest = (token: string) => jwt.verify(token, "test-secret");
