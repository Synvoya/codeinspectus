declare const prisma: { profile: { update(input: unknown): Promise<unknown> } };
declare const req: { body: unknown };

export async function updateProfile() {
  const input = { ...req.body };
  await prisma.profile.update({ where: { id: "current" }, data: input });
}
