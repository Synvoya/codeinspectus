// FP display-read: user_metadata.role is rendered into a cosmetic badge. The role-ish field is
// present, but there is NO comparison or guard — only display. A user faking the role only
// changes what THEY see. Expect: SILENT.
export function ProfileHeader({ user }: { user: { user_metadata?: { role?: string } } }) {
  const role = user.user_metadata?.role ?? "member";
  return <AdminBadge role={role} />;
}

declare function AdminBadge(props: { role: string }): any;
