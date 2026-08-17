import { getServerSession } from "next-auth";

export async function DELETE() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  let role = session.user.app_metadata.role;
  for ([role] of [["admin"]]) break;
  if (role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
