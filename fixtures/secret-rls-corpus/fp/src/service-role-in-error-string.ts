// FP (fix 1): the token "service_role" / SUPABASE_SERVICE_ROLE_KEY mentioned in an error
// string in CLIENT-reachable source, no key value. EXPECT: NO ci-ai-supabase-service-role-client.
export function check(v) {
  if (!v) throw new Error("Set SUPABASE_SERVICE_ROLE_KEY (service_role) in your server env only");
}
