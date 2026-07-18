alter policy "document reader" on public.policy_documents
  using (auth.uid() = owner_id);
