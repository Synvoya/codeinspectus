declare const prisma: { user: { update(input: unknown): Promise<unknown> } };

export async function PATCH(request: Request) {
  const body = await request.json();
  await prisma.user.update({ where: { id: "current" }, data: body });
  return Response.json({ ok: true });
}
