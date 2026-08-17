import { withSupabase } from "npm:@supabase/server";
import Stripe from "npm:stripe";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);

export default {
  fetch: withSupabase({ auth: "none" }, async (request, ctx) => {
    try {
      stripe.webhooks.constructEvent(
        "fixed" + await request.text(),
        "fixed" + (request.headers.get("stripe-signature") ?? ""),
        Deno.env.get("STRIPE_WEBHOOK_SECRET")!,
      );
    } catch {
      return new Response("Invalid", { status: 401 });
    }
    return Response.json(await ctx.supabaseAdmin.from("events").select());
  }),
};
