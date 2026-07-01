-- CG-25b B-12 TP — permissive policies on storage.objects expose every stored file
-- (the storage arm of the CVE-2025-48757 class). Must fire ci-ai-storage-rls-public.
create policy "public read" on storage.objects for select using (true);
create policy "public write" on storage.objects for insert with check (true);
