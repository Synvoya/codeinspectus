import { auth as clerkAuth } from "@clerk/nextjs/server";

export async function POST() {
  const { userId, sessionClaims } = await clerkAuth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  if (!sessionClaims.metadata?.isAdmin) {
    return new Response("Forbidden", { status: 403 });
  }
  return Response.json(await createAdminInvite());
}
