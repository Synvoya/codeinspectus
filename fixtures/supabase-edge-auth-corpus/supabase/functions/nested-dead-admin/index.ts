import { createClient } from "npm:@supabase/supabase-js";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);
Deno.serve(async () => {
  const neverCalled = async () => db.from("accounts").select();
  void neverCalled;
  return Response.json({ ok: true });
});
