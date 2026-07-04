// TP inline: authorization decision reads client-writable user_metadata.role.
// Expect: FIRE (high, medium-confidence). user_metadata is self-writable via /auth/v1/user,
// so any authenticated user can set role='admin' and pass this check.
export async function handler(user: { user_metadata: { role?: string } }) {
  if (user.user_metadata.role === "admin") {
    await deleteAllUsers(); // privileged action gated on client-writable data
  }
}

declare function deleteAllUsers(): Promise<void>;
