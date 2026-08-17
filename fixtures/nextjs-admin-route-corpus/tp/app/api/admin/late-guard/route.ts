import { getServerSession } from "next-auth";

export async function PATCH() {
  const session = await getServerSession();
  const result = await updateBillingRecord();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  if (session.user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(result);
}
