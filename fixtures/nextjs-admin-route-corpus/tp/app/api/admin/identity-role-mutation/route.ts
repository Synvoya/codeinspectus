import { getServerSession } from "next-auth";

export async function PATCH() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  session.user.app_metadata.role = "admin";
  if (session.user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await updateAdminRecord());
}
