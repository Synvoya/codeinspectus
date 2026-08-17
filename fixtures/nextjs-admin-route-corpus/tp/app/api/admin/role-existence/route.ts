import { getServerSession } from "next-auth";

export async function GET() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  if (!session.user.role) return new Response("Forbidden", { status: 403 });
  return Response.json(await loadAdminData());
}
