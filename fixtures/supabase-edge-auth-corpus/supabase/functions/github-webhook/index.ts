import { Webhooks } from "@octokit/webhooks";
import { createClient } from "npm:@supabase/supabase-js";

const webhooks = new Webhooks({ secret: Deno.env.get("GITHUB_WEBHOOK_SECRET")! });
const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);
Deno.serve(async (request) => {
  const verified = await webhooks.verify(await request.text(), request.headers.get("x-hub-signature-256")!);
  if (!verified) return new Response("Invalid signature", { status: 401 });
  return Response.json(await supabaseAdmin.from("events").select());
});
