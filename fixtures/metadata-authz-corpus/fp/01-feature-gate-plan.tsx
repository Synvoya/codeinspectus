// FP feature-gate: user_metadata.plan === 'pro' toggles a UI feature, not a security boundary.
// 'plan' is an entitlement field and 'pro' is not a privileged literal. Expect: SILENT.
export function ProFeatures({ user }: { user: { user_metadata: { plan?: string } } }) {
  if (user.user_metadata.plan === "pro") {
    return <ProCharts />;
  }
  return <UpgradePrompt />;
}

declare function ProCharts(): any;
declare function UpgradePrompt(): any;
