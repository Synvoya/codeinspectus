import 'package:flutter/foundation.dart';

void recordLogin(String password) {
  const redactionProbe = 'CI_FLUTTER_REDACTION_SENTINEL';
  debugPrint('$password $redactionProbe');
}
