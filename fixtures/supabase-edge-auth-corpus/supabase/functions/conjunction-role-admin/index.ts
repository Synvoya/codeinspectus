import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: "user" }, async (_request, ctx) => {
    const featureEnabled = false;
    if (ctx.userClaims.app_metadata.role !== "admin" && featureEnabled) return new Response("Forbidden", { status: 403 });
    return Response.json(await ctx.supabaseAdmin.from("accounts").select());
  }),
};
