import { randomUUID } from "node:crypto";

declare function refresh(): Promise<void>;

export async function POST() {
  const token = randomUUID();
  try {
    await refresh();
    return Response.json({ ok: true, issued: token.length });
  } catch ({ token }) {
    return Response.json({ token });
  }
}
