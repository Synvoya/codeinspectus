await supabase.auth.signInWithPassword({
  email,
  password,
});
