import { withSupabase } from "npm:@supabase/server";
import { Webhooks } from "npm:@octokit/webhooks";

const webhooks = new Webhooks({ secret: Deno.env.get("GITHUB_WEBHOOK_SECRET")! });

export default {
  fetch: withSupabase({ auth: "none" }, async (_request, ctx) => {
    const verified = await webhooks.verify("fixed-body", "fixed-signature");
    if (!verified) return new Response("Invalid", { status: 401 });
    return Response.json(await ctx.supabaseAdmin.from("events").select());
  }),
};
