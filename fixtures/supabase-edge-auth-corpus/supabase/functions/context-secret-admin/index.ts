import { createSupabaseContext } from "npm:@supabase/server";

Deno.serve(async (request) => {
  const { data: ctx, error } = await createSupabaseContext(request, { auth: "secret" });
  if (error) return new Response("Unauthorized", { status: 401 });
  return Response.json(await ctx.supabaseAdmin.from("jobs").select());
});
