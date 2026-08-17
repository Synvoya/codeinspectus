import { withSupabase } from "npm:@supabase/server";

Deno.serve(withSupabase({ auth: "user" }, async (_request, ctx) => {
  return Response.json({ userId: ctx.userClaims.id });
}));
