import { getServerSession } from "next-auth";

export async function GET() {
  const { user, error } = await getServerSession() as any;
  if (error || !user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin" || !user.app_metadata.isAdmin) return new Response("Forbidden", { status: 403 });
  return Response.json(await loadAdminData());
}
