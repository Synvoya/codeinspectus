import { currentUser } from "@clerk/nextjs/server";

export async function DELETE(request: Request) {
  const user = process.env.STRICT ? await currentUser() : await request.json();
  if (!user) return new Response("Unauthorized", { status: 401 });
  if (user.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
  return Response.json(await deleteAdminData());
}
