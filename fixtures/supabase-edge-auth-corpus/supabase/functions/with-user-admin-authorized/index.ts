import { withSupabase } from "npm:@supabase/server";

Deno.serve(withSupabase({ auth: "user" }, async (_request, ctx) => {
  if (ctx.userClaims.app_metadata.role !== "admin") {
    return new Response("Forbidden", { status: 403 });
  }
  return Response.json(await ctx.supabaseAdmin.from("accounts").select());
}));
