await supabase.auth.signUp({
  email,
  password,
  options: { captchaToken },
});

await supabase.auth.signInWithOtp({
  email,
  options: { shouldCreateUser: false },
});
