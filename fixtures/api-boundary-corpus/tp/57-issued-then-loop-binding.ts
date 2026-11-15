import { randomUUID } from "node:crypto";

declare function remember(value: string): Promise<void>;
declare function listStoredTokens(): Promise<Array<{ token: string }>>;

export async function GET() {
  const token = randomUUID();
  await remember(token);
  for (const { token } of await listStoredTokens()) {
    return Response.json({ token });
  }
  return Response.json({ ok: true });
}
