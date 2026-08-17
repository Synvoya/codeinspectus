import { createClient } from "npm:@supabase/supabase-js";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SECRET_KEY")!);
Deno.serve(async () => Response.json(await admin.from("accounts").select()));
