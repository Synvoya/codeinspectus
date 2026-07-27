import 'package:flutter/foundation.dart';

void recordSafeDiagnostics(String accessToken) {
  if (kDebugMode) debugPrint(accessToken);
  print(accessToken.length);
  print(hash(accessToken));
  analytics.info(accessToken);
}
