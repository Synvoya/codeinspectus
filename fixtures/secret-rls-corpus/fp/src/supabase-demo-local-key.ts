"use client";
// FP (fix 2): the PUBLIC Supabase local-dev demo service_role key (iss: supabase-demo) in a
// CLIENT file. EXPECT: NO ci-ai-supabase-service-role-client (AI skips demo iss) AND NO
// codeinspectus-supabase-service-role (gitleaks allowlisted).
export const localDevKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.ZmFrZV9zaWduYXR1cmVfbm90X3JlYWxfZm9yX3Rlc3Rfb25seQ";
