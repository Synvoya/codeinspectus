import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> initializeSupabase() async {
  const publishableKey = String.fromEnvironment('SUPABASE_PUBLISHABLE_KEY');
  await Supabase.initialize(
    url: 'https://fixture-project.supabase.co',
    anonKey: publishableKey,
  );
}
