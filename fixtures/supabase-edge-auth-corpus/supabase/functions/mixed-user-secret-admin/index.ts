import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: ["user", "secret"] }, async (_request, ctx) => {
    return Response.json(await ctx.supabaseAdmin.from("accounts").select());
  }),
};
