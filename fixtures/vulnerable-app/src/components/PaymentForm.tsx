// FIXTURE — bonus planted issue: a secret behind a client-exposed env prefix.
// Frameworks ship NEXT_PUBLIC_/VITE_ vars to the browser. Detected by:
// CodeInspectus AI client-secrets check (ci-ai-public-env-secret). CWE-798.
export function PaymentForm() {
  // This value is bundled into the client and visible to every visitor.
  const stripeSecret = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
  return stripeSecret;
}

// Safe equivalent — a PUBLISHABLE key behind a public prefix is fine and should
// NOT be flagged (precision check): name doesn't match the secret heuristic.
export function publishable() {
  return process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;
}
