import { createClient } from "npm:@supabase/supabase-js";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
Deno.serve(async () => Response.json(await db.from("accounts").select()));
