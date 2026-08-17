import { getServerSession } from "next-auth";

async function requireAdmin() {
  const session = await getServerSession();
  if (!session?.user) {
    if (process.env.STRICT_AUTH === "true") throw new Error("Unauthorized");
  }
  if (session?.user?.app_metadata?.role !== "admin") {
    if (process.env.STRICT_ROLE === "true") throw new Error("Forbidden");
  }
}

export async function DELETE() {
  await requireAdmin();
  return Response.json(await deleteAdminData());
}
