import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

Future<void> persistSafePreferences(String fcmToken, String accessToken) async {
  final preferences = await SharedPreferences.getInstance();
  await preferences.setString('fcm_token', fcmToken);
  await preferences.setString('access_token_hash', hash(accessToken));

  const secureStorage = FlutterSecureStorage();
  await secureStorage.write(key: 'access_token', value: accessToken);
}

void unrelatedReceiver(FakePreferences preferences, String accessToken) {
  preferences.setString('access_token', accessToken);
}
