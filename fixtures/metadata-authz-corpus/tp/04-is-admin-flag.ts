// TP role-ish boolean flag: is_admin off user_metadata used as a bare if-condition guard.
// The field name is authz-semantic and user_metadata is client-writable. Expect: FIRE.
export function canManage(user: { user_metadata: { is_admin?: boolean } }) {
  if (user.user_metadata.is_admin) {
    return openAdminPanel();
  }
  return null;
}

declare function openAdminPanel(): unknown;
