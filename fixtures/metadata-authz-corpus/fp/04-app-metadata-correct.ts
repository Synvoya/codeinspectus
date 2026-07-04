// TN correct: authorization keyed off server-only app_metadata.role — the CORRECT field.
// app_metadata is NOT client-writable (only the service role / admin API can set it).
// This is exactly the fix the rule recommends. Expect: SILENT.
export function requireAdmin(user: { app_metadata: { role?: string } }): boolean {
  if (user.app_metadata.role === "admin") {
    return true;
  }
  return false;
}
