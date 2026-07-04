// TP permissions array: permissions.includes('admin') off user_metadata gating a privileged
// action. Expect: FIRE (role-ish field + .includes() membership guard).
export function authorize(user: { user_metadata: { permissions?: string[] } }) {
  if (user.user_metadata.permissions?.includes("admin")) {
    performPrivilegedAction();
  }
}

declare function performPrivilegedAction(): void;
