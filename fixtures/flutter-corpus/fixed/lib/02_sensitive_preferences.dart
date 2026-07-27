import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<void> persistAccessToken(String accessToken) async {
  const secureStorage = FlutterSecureStorage();
  await secureStorage.write(key: 'access_token', value: accessToken);
}
