// TP destructured: role destructured off user_metadata, then compared in a guard.
// Expect: FIRE (intrafile taint through the destructuring binding).
export function guard(user: { user_metadata: { role?: string } }) {
  const { role } = user.user_metadata;
  if (role === "admin") {
    grantAdminAccess();
  }
}

declare function grantAdminAccess(): void;
