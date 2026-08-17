import { withSupabase } from "npm:@supabase/server";
import Stripe from "npm:stripe";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);

export default {
  fetch: withSupabase({ auth: "none" }, async (_request, ctx) => {
    try {
      stripe.webhooks.constructEvent("fixed-body", "fixed-signature", Deno.env.get("STRIPE_WEBHOOK_SECRET")!);
    } catch {
      return new Response("Invalid", { status: 401 });
    }
    return Response.json(await ctx.supabaseAdmin.from("events").select());
  }),
};
