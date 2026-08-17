import { createSupabaseContext } from "npm:@supabase/server";

Deno.serve(async () => {
  const { data: ctx, error } = await createSupabaseContext(new Request("https://fixed.invalid"), { auth: "user" });
  if (error) return new Response("Unauthorized", { status: 401 });
  return Response.json(await ctx.supabaseAdmin.from("accounts").select());
});
