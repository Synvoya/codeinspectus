import { getServerSession } from "next-auth";

export async function DELETE(request: Request) {
  const session = (await getServerSession()) || { user: await request.json() };
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  if (session.user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
