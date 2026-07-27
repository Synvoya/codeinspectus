import 'package:webview_flutter/webview_flutter.dart';

void openAllowlistedLink() {
  final deepLink = Uri.base.queryParameters['target'];
  final incomingUri = Uri.parse(deepLink!);
  final controller = WebViewController();
  controller.setJavaScriptMode(JavaScriptMode.unrestricted);
  if (incomingUri.scheme != 'https' || incomingUri.host != 'trusted.mobile-fixture.tld') {
    return;
  }
  controller.loadRequest(incomingUri);
}
