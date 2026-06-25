// FIXTURE — planted issue #1: hard-coded Stripe LIVE secret key in
// client-reachable source (src/). Detected by: CodeInspectus AI client-secrets
// check (ci-ai-client-hardcoded-secret) AND Gitleaks. CWE-798/CWE-312.
// INTENTIONAL FAKE TEST DATA -- not a real credential; allowlisted in /.gitleaks.toml.
export const STRIPE_SECRET = "sk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP1rE5wB9mNqK7";

export const config = {
  stripeSecret: STRIPE_SECRET,
  appName: "vulnerable-app",
};
