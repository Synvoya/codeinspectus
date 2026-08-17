import { getServerSession } from "next-auth";

async function isAdmin() {
  const session = await getServerSession();
  if (!session?.user) return false;
  if (session.user.app_metadata.role !== "admin") return false;
  return true;
}

export async function DELETE() {
  if (!await isAdmin()) return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
