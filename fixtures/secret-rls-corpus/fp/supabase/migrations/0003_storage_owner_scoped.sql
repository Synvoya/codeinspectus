-- CG-25b B-12 FP — must NOT fire:
--  - an owner-scoped storage.objects policy (not world-readable)
--  - a USING(true) policy on a genuine system table (auth.*) — system schemas stay skipped,
--    so re-enabling storage.objects must not reintroduce the CG-18 system-schema FP.
create policy "own files" on storage.objects for select using (auth.uid() = owner);
create policy "internal read" on auth.users for select using (true);
