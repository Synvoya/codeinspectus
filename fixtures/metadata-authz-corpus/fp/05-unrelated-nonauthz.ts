// TN unrelated: user_metadata read in a non-authz comparison (locale) and a plain read
// (onboarding step). No role-ish field, no privileged literal. Expect: SILENT.
export function setup(user: { user_metadata: { locale?: string; onboarding_step?: number } }) {
  if (user.user_metadata.locale === "en-US") {
    loadEnglish();
  }
  const step = user.user_metadata.onboarding_step;
  return step;
}

declare function loadEnglish(): void;
