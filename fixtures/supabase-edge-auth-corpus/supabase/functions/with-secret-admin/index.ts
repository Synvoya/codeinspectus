import { withSupabase } from "npm:@supabase/server";

Deno.serve(withSupabase({ auth: "secret:cron" }, async (_request, ctx) => {
  return Response.json(await ctx.supabaseAdmin.from("jobs").select());
}));
