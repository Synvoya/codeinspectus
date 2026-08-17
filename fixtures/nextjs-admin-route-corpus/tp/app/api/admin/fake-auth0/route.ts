import { getSession } from "@auth0/nextjs-auth0-evil";

export async function GET() {
  const session = await getSession();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  if (session.user.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await loadAdminData());
}
