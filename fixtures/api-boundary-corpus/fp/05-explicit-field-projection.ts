declare const prisma: { user: { create(input: unknown): Promise<unknown> } };

export async function POST(request: Request) {
  const body = (await request.json()) as { displayName: string; timezone: string };
  const input = { displayName: body.displayName, timezone: body.timezone };
  await prisma.user.create({ data: input });
  return Response.json({ ok: true });
}
