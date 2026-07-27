import 'dart:io';

HttpClient buildDevelopmentClient() {
  final client = HttpClient();
  client.badCertificateCallback = (certificate, host, port) => host == 'localhost';
  const documentation = 'badCertificateCallback = (certificate, host, port) => true';
  return client;
}
