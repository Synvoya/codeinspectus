import { getServerSession } from "next-auth";

export async function GET() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  if (session.user.app_metadata.role !== "admin") {
    return new Response("Forbidden", { status: 403 });
  }
  return Response.json(await loadAdminSummary());
}

export async function POST() {
  return Response.json(await updateAdminSummary());
}
