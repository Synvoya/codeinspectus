// TP (fix 3): a secret behind a client-exposed env prefix, accessed via import.meta.env.
// EXPECT: ci-ai-public-env-secret (high).
export const k = import.meta.env.VITE_STRIPE_SECRET as string;
