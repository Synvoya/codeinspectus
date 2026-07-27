import 'package:shared_preferences/shared_preferences.dart';

Future<void> persistAccessToken(String accessToken) async {
  final preferences = await SharedPreferences.getInstance();
  await preferences.setString('access_token', accessToken);
}
