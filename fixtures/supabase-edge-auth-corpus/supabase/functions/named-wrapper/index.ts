import { withSupabase } from "npm:@supabase/server";

const secured = withSupabase({ auth: "secret" }, async (_request, ctx) => {
  return Response.json(await ctx.supabaseAdmin.from("jobs").select());
});

Deno.serve(secured);
