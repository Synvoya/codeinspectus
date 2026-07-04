// TP privileged-literal arm: a NON-role field off user_metadata compared to a privileged literal
// ('superadmin'). Demonstrates the literal-based fire — covers an authz check keyed off an
// arbitrary field name (incl. a tier/plan field used as a real role gate). Expect: FIRE (arm B).
export function gate(user: { user_metadata: { access_level?: string } }) {
  if (user.user_metadata.access_level === "superadmin") {
    wipeDatabase();
  }
}

declare function wipeDatabase(): void;
