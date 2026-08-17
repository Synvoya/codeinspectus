import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: ["user", "secret"] }, async (request, ctx) => {
    const requiredMode = (await request.json()).mode;
    if (ctx.authMode !== requiredMode) return new Response("Forbidden", { status: 403 });
    return Response.json(await ctx.supabaseAdmin.from("accounts").select());
  }),
};
