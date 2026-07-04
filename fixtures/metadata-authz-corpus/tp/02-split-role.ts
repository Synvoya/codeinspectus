// TP split-variable: role pulled to a const, then compared on a later line.
// Needs intrafile taint (the source read and the comparison are on different lines).
// Expect: FIRE.
export function isAdmin(user: { user_metadata?: { role?: string } }): boolean {
  const role = user.user_metadata?.role;
  // ... other logic ...
  return role === "admin";
}
