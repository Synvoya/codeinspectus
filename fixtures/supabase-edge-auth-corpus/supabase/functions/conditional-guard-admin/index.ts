import { createSupabaseContext } from "npm:@supabase/server";

Deno.serve(async (request) => {
  const { data: ctx, error } = await createSupabaseContext(request, { auth: "user" });
  if (error) {
    if (Deno.env.get("DEBUG")) return new Response("Unauthorized", { status: 401 });
  }
  return Response.json(await ctx.supabaseAdmin.from("accounts").select());
});
