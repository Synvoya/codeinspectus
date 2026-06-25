-- TP (fix 4): a public table created without RLS, in a real supabase/ migration.
-- EXPECT: ci-ai-rls-missing (high) on 'profiles'.
create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  email text
);
