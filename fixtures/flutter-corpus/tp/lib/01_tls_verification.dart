import 'dart:io';

HttpClient buildInsecureClient() {
  final client = HttpClient();
  client.badCertificateCallback = (certificate, host, port) => true;
  return client;
}
