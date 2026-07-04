// FP display: benign profile fields off user_metadata, no authorization. Expect: SILENT.
export function profileCard(user: { user_metadata: { full_name?: string; avatar_url?: string } }) {
  const name = user.user_metadata.full_name;
  const avatar = user.user_metadata.avatar_url;
  return { name, avatar };
}
