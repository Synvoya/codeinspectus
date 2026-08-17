import { getServerSession } from "next-auth";

export async function POST(request: Request) {
  const session = await getServerSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const claims = await request.json();
  if (claims.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await createAdminRecord());
}
