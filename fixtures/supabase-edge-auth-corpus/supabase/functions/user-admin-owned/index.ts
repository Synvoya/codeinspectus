import { withSupabase } from "npm:@supabase/server";

Deno.serve(withSupabase({ auth: "user" }, async (_request, ctx) => {
  const account = { owner_id: "another-user" };
  if (account.owner_id !== ctx.userClaims.id) return new Response("Forbidden", { status: 403 });
  return Response.json(await ctx.supabaseAdmin.from("accounts").select());
}));
