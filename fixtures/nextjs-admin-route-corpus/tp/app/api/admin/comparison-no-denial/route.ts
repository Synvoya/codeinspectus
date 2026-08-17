import { getServerSession } from "next-auth";

export async function DELETE() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const isAdmin = session.user.app_metadata.isAdmin;
  if (!isAdmin) console.warn("non-admin caller");
  return Response.json(await deleteAdminRecord());
}
