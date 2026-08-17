import { createClient } from "npm:@supabase/supabase-js";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);
export default async function handler() {
  return Response.json(await admin.from("accounts").select());
}
