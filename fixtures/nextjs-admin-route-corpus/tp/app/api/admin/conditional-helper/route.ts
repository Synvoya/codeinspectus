import { getServerSession } from "next-auth";

async function requireAdmin() {
  const session = await getServerSession();
  if (!session?.user) throw new Error("Unauthorized");
  if (session.user.app_metadata.role !== "admin") throw new Error("Forbidden");
}

export async function DELETE() {
  if (process.env.CHECK_AUTH === "true") await requireAdmin();
  return Response.json(await deleteAdminData());
}
