declare const schema: {
  parse(value: unknown): { displayName: string };
  parseAsync(value: unknown): Promise<{ displayName: string }>;
};
declare const prisma: { user: { update(input: unknown): Promise<unknown> } };

export async function PATCH(request: Request) {
  const body = await request.json();
  const input = schema.parse(body);
  await prisma.user.update({ where: { id: "current" }, data: input });
  return Response.json({ ok: true });
}

export async function PATCH_ASYNC(request: Request) {
  const input = await schema.parseAsync(await request.json());
  await prisma.user.update({ where: { id: "current" }, data: input });
  return Response.json({ ok: true });
}
