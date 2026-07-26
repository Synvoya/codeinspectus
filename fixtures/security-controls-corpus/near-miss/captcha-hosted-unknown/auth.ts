// The hosted project may enable CAPTCHA, but no authoritative repository setting proves it.
await supabase.auth.signInWithPassword({ email, password });
