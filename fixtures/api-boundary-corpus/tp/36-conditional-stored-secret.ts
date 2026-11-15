declare function newId(prefix: string): string;
declare function loadHook(id: string): Promise<{ secret: string }>;

export async function PATCH(request: Request) {
  const body = (await request.json()) as { id: string; rotate?: boolean };
  const hook = await loadHook(body.id);
  const secret = body.rotate ? newId("hook") : hook.secret;
  return Response.json({ ok: true, secret });
}
