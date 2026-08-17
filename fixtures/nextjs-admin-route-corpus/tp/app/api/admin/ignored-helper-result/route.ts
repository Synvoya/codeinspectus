import { getServerSession } from "next-auth";

async function requireAdmin() {
  const session = await getServerSession();
  if (!session?.user) return false;
  if (session.user.app_metadata.role !== "admin") return false;
  return true;
}

export async function DELETE() {
  await requireAdmin();
  return Response.json(await deleteAdminData());
}
