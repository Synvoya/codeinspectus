import * as argon2 from "argon2";
import { createVerify } from "crypto";
export async function login(hash: string, password: string, sig: string, key: string) {
  const ok = await argon2.verify(hash, password);
  const verifier = createVerify("SHA256");
  return ok && verifier.verify(key, sig);
}
