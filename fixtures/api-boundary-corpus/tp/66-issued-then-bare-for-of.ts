import { randomUUID } from "node:crypto";

declare const db: { stored(): Promise<string[]> };

export async function GET() {
  let token = randomUUID();
  for (token of await db.stored()) {
    // keeps the last stored token
  }
  return Response.json({ token });
}
