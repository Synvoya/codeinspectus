import { createClient } from "npm:@supabase/supabase-js";

const userClient = createClient("https://example.supabase.co", "publishable-key");
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);

Deno.serve(async (request) => {
  const fake = new Request("https://attacker.invalid", { headers: { Authorization: "fixed" } });
  const { data, error } = await userClient.auth.getUser(fake.headers.get("Authorization") + request.url);
  if (error || !data.user) return new Response("Unauthorized", { status: 401 });
  return Response.json(await admin.from("accounts").select());
});
