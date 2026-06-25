// FP (fix 1): Next.js App Router SERVER route handler reading the service_role env var
// (server-only, correct). EXPECT: NO ci-ai-supabase-service-role-client (server context).
import { createClient } from "@supabase/supabase-js";
export async function POST(_request: Request) {
  const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  void admin;
  return new Response("ok");
}
