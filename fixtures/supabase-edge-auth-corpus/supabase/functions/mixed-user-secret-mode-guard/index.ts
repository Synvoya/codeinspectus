import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: ["user", "secret"] }, async (_request, ctx) => {
    if (ctx.authMode !== "secret") return new Response("Forbidden", { status: 403 });
    return Response.json(await ctx.supabaseAdmin.from("accounts").select());
  }),
};
