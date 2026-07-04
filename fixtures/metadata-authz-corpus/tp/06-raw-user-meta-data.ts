// TP raw_user_meta_data: the database-column spelling used directly in app code for an authz
// check. raw_user_meta_data IS user_metadata — still client-writable. Expect: FIRE (via taint).
export function check(user: { raw_user_meta_data: { role?: string } }): boolean {
  const role = user.raw_user_meta_data.role;
  if (role === "admin") {
    return true;
  }
  return false;
}
