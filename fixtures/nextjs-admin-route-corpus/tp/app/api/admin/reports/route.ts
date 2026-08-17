import { getServerSession } from "next-auth";

export async function GET() {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  return Response.json(await loadAdminReports());
}
