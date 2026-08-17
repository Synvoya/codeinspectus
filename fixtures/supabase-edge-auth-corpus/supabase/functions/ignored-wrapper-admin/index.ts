import { withSupabase } from "npm:@supabase/server";
import { createClient } from "npm:@supabase/supabase-js";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);

Deno.serve(async () => {
  withSupabase({ auth: "user" }, async () => Response.json({ ignored: true }));
  return Response.json(await admin.from("accounts").select());
});
