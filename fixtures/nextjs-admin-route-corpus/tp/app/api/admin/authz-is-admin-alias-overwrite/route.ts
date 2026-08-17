import { getServerSession } from "next-auth";

export async function DELETE() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  let isAdmin = session.user.isAdmin;
  isAdmin = true;
  if (!isAdmin) return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
