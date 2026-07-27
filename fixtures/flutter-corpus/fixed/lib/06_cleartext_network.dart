import 'package:dio/dio.dart';

Dio buildApiClient() {
  return Dio(BaseOptions(baseUrl: 'https://api.mobile-fixture.tld/v1/status'));
}
