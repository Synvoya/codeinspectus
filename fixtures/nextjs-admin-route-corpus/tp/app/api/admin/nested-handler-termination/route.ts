import { getServerSession } from "next-auth";

export async function GET() {
  const session = await getServerSession();
  if (!session?.user) {
    if (process.env.STRICT_AUTH === "true") return new Response("Unauthorized", { status: 401 });
  }
  if (session?.user?.app_metadata?.role !== "admin") {
    if (process.env.STRICT_ROLE === "true") return new Response("Forbidden", { status: 403 });
  }
  return Response.json(await loadAdminData());
}
