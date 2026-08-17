import { getServerSession } from "next-auth";

export async function POST() {
  let session: any;
  if (!session) return new Response("Unauthorized", { status: 401 });
  session = await getServerSession();
  if (session.user.app_metadata.role !== "admin") {
    return new Response("Forbidden", { status: 403 });
  }
  return Response.json(await deleteAdminRecord());
}
