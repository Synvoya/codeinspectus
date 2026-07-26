await supabase.auth.signUp({
  email,
  password,
  options: { captchaToken },
});

await supabase.auth.signInWithPassword({
  email,
  password,
  options: { captchaToken },
});

await supabase.auth.resetPasswordForEmail(email, {
  redirectTo: "https://example.test/reset",
  captchaToken,
});
