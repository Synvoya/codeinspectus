import { getServerSession } from "next-auth";

export async function GET() {
  const session = getServerSession();
  if (!session) return new Response("Unauthorized", { status: 401 });
  if ((session as any).user.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await loadAdminData());
}
