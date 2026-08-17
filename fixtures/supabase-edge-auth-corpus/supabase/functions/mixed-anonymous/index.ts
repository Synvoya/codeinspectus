import { withSupabase } from "npm:@supabase/server";

Deno.serve(withSupabase({ auth: ["user", "none"] }, async () => Response.json({ ok: true })));
