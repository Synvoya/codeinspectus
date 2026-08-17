import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: "user" }, async (request, ctx) => {
    const requiredRole = (await request.json()).role;
    if (ctx.userClaims.app_metadata.role !== requiredRole) return new Response("Forbidden", { status: 403 });
    return Response.json(await ctx.supabaseAdmin.from("accounts").select());
  }),
};
