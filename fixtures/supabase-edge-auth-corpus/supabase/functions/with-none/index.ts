import { withSupabase } from "npm:@supabase/server";

Deno.serve(withSupabase({ auth: "none" }, async () => Response.json({ ok: true })));
