declare const env: { DB: unknown };
declare function verifyPassword(request: Request): Promise<{ id: string } | null>;
declare function createSession(env: unknown, userId: string): Promise<string>;
declare function newId(prefix: string): string;

export async function POST(request: Request) {
  const user = await verifyPassword(request);
  if (!user) return Response.json({ error: "invalid credentials" }, { status: 401 });
  const token = await createSession(env, user.id);
  return Response.json({ ok: true, token });
}

export async function PATCH(request: Request) {
  const body = (await request.json()) as { rotate?: boolean };
  const secret = body.rotate ? newId("hook") : null;
  // Shown once, when it is rotated.
  return Response.json({ ok: true, ...(secret ? { secret } : {}) });
}
