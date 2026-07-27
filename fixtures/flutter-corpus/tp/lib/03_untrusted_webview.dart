import 'package:webview_flutter/webview_flutter.dart';

void openIncomingLink() {
  final deepLink = Uri.base.queryParameters['target'];
  final controller = WebViewController();
  controller.setJavaScriptMode(JavaScriptMode.unrestricted);
  controller.loadRequest(Uri.parse(deepLink!));
}
