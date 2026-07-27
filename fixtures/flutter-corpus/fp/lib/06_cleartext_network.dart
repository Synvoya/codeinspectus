import 'package:dio/dio.dart';
import 'package:url_launcher/url_launcher.dart';

Future<void> useSafeEndpoints() async {
  final client = Dio(BaseOptions(baseUrl: 'https://api.mobile-fixture.tld'));
  await client.get('http://localhost:8080/health');
  await client.get('http://10.0.2.2/health');
  await launchUrl(Uri.parse('http://api.mobile-fixture.tld/help'));
  const documentation = 'http://example.com/not-a-network-call';
}
