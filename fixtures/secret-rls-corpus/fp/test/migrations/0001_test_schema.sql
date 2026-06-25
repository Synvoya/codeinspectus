-- FP (fix 4): a public table without RLS, but in a TEST fixture migration path.
-- EXPECT: NO ci-ai-rls-missing (test/example path excluded).
create table public.widgets (id int primary key, name text);
