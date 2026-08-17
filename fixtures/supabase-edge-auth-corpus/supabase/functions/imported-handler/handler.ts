import { createClient } from "npm:@supabase/supabase-js";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);
export default async function handler() {
  return Response.json(await db.from("accounts").select());
}
