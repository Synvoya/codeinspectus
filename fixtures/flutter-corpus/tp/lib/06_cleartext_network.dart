import 'package:dio/dio.dart';

Dio buildApiClient() {
  return Dio(BaseOptions(baseUrl: 'http://api.mobile-fixture.tld/v1/status'));
}
