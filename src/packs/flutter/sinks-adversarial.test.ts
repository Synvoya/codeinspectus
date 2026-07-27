import { describe, expect, test } from "vitest";

import type { Finding } from "../../types.js";
import { parseDartSource } from "./dart.js";
import type { FlutterProject, FlutterProjectInput } from "./project.js";
import { runFlutterCleartextNetwork } from "./cleartext.js";
import { runFlutterSensitiveLog } from "./logs.js";
import { runFlutterTlsVerificationDisabled } from "./tls.js";

function project(source: string): FlutterProject {
  return {
    target: "/virtual/flutter",
    root: "/virtual/flutter",
    files: [parseDartSource("lib/main.dart", source)],
  };
}

function findings(
  runner: (input: FlutterProjectInput) => Promise<Finding[]>,
  source: string,
): Promise<Finding[]> {
  return runner(project(source));
}

describe("Flutter logging import provenance", () => {
  test("requires dart:developer provenance for developer.log and an import alias", async () => {
    await expect(findings(runFlutterSensitiveLog, `
      developer.log(accessToken);
      dev.log(refreshToken);
    `)).resolves.toHaveLength(0);

    await expect(findings(runFlutterSensitiveLog, `
      import 'dart:developer';
      log(accessToken);
    `)).resolves.toHaveLength(1);

    await expect(findings(runFlutterSensitiveLog, `
      import 'dart:developer' as dev;
      dev.log(accessToken);
    `)).resolves.toHaveLength(1);
  });
});

describe("Flutter cleartext client provenance", () => {
  test("does not trust conventional http/dio receiver names without proof", async () => {
    await expect(findings(runFlutterCleartextNetwork, `
      http.get(Uri.parse('http://api.real-service.tld/private'));
      dio.get('http://api.real-service.tld/private');
    `)).resolves.toHaveLength(0);
  });

  test("retains explicit package:http and Dio construction positives", async () => {
    await expect(findings(runFlutterCleartextNetwork, `
      import 'package:http/http.dart' as http;
      http.get(Uri.parse('http://api.real-service.tld/private'));
      final dio = Dio();
      dio.get('http://api.real-service.tld/private');
      Dio().get('http://api.real-service.tld/private');
    `)).resolves.toHaveLength(3);
  });
});

describe("Flutter TLS callback precision", () => {
  test("recognizes parenthesized true and a final unconditional return", async () => {
    await expect(findings(runFlutterTlsVerificationDisabled, `
      first.badCertificateCallback = (_) => ((true));
      second.badCertificateCallback = (cert, host, port) {
        audit(host);
        return (true);
      };
    `)).resolves.toHaveLength(2);
  });

  test("keeps exact debug-only and conditionally accepting callbacks silent", async () => {
    await expect(findings(runFlutterTlsVerificationDisabled, `
      if (kDebugMode) {
        debugClient.badCertificateCallback = (_) => true;
      }
      conditional.badCertificateCallback = (cert, host, port) {
        if (host == 'dev.internal') return true;
        return false;
      };
      throwing.badCertificateCallback = (cert, host, port) {
        if (host.isEmpty) throw StateError('host');
        return true;
      };
    `)).resolves.toHaveLength(0);
  });
});
