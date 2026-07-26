await supabase.auth.signUp({
  email,
  password,
});

await supabase.auth.signInWithPassword({
  email,
  password,
});

await supabase.auth.resetPasswordForEmail(email, {
  redirectTo: "https://example.test/reset",
});
