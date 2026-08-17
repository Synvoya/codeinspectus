import { createClient } from "npm:@supabase/supabase-js";

const userClient = createClient("https://example.supabase.co", "publishable-key");
const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);

Deno.serve(async (request) => {
  const rows = await admin.from("accounts").select();
  const { data, error } = await userClient.auth.getUser(request.headers.get("Authorization") ?? "");
  if (error || !data.user) return new Response("Unauthorized", { status: 401 });
  return Response.json(rows);
});
