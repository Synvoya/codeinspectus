import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: "user" }, async (request, ctx) => {
    const body = await request.json();
    if (ctx.userClaims.app_metadata.role !== body.requiredRole) return new Response("Forbidden", { status: 403 });
    return Response.json(await ctx.supabaseAdmin.from("accounts").select());
  }),
};
