import { withSupabase } from "npm:@supabase/server";

export default {
  fetch: withSupabase({ auth: "user" }, async (_request, ctx) => {
    if (ctx.userClaims.app_metadata.role !== "admin") return new Response("Forbidden", { status: 403 });
    const { supabaseAdmin } = ctx;
    return Response.json(await supabaseAdmin.from("accounts").select());
  }),
};
