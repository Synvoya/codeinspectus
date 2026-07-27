import 'package:supabase_flutter/supabase_flutter.dart';

Future<void> initializeSupabase() async {
  const serviceRoleKey = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');
  await Supabase.initialize(
    url: 'https://fixture-project.supabase.co',
    anonKey: serviceRoleKey,
  );
}
