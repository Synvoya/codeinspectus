import { createSupabaseContext } from "npm:@supabase/server";

Deno.serve(async (request) => {
  const { data: ctx, error } = await createSupabaseContext(request, { auth: "user" });
  if (error) return new Response("Unauthorized", { status: 401 });
  return Response.json({ userId: ctx.userClaims.id });
});
