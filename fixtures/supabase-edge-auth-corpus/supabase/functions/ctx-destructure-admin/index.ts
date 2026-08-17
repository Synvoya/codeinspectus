import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: "user" }, async (_request, ctx) => {
    const { supabaseAdmin } = ctx;
    return Response.json(await supabaseAdmin.from("accounts").select());
  }),
};
