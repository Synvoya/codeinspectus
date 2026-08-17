import { withSupabase } from "npm:@supabase/server";
import { createClient } from "npm:@supabase/supabase-js";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);

Deno.serve(async () => {
  const neverCalled = () => withSupabase({ auth: "user" }, async () => Response.json({ ok: true }));
  void neverCalled;
  return Response.json(await admin.from("accounts").select());
});
