// FP (fix 3): a public-prefixed env var NAME inside a help/error string (no env access).
// EXPECT: NO ci-ai-public-env-secret.
export const help = "Please set NEXT_PUBLIC_FOO_SECRET in your .env file to enable payments";
