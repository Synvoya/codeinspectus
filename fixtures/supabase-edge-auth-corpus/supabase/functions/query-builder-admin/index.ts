import { createClient } from "npm:@supabase/supabase-js";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);

Deno.serve(async () => {
  const query = db.from("accounts");
  return Response.json(await query.select());
});
