import 'package:flutter/foundation.dart';

void recordSafeDiagnostics(String accessToken) {
  if (kDebugMode) debugPrint(accessToken);
  print(accessToken.length);
  print(hash(accessToken));
  analytics.info(accessToken);
}

// 4.1 M9: the sensitive word is in the literal text; the logged value is the exception.
final _log = Logger('AuthGuard');

void reportValidationFailure(Object e) {
  _log.warning('Could not validate the access token with the server: $e');
  debugPrint('password reset failed: ${e.runtimeType}');
}
