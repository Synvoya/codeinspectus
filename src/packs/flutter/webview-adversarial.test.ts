import { describe, expect, test } from "vitest";

import type { Finding } from "../../types.js";
import { parseDartSource } from "./dart.js";
import type { FlutterProject } from "./project.js";
import { runFlutterWebViewUntrustedContent } from "./webview.js";

function project(source: string): FlutterProject {
  return {
    target: "/virtual/flutter",
    root: "/virtual/flutter",
    files: [parseDartSource("lib/main.dart", source)],
  };
}

async function findings(source: string): Promise<Finding[]> {
  return runFlutterWebViewUntrustedContent(project(source));
}

describe("Flutter WebView source-order and scope precision", () => {
  test("applies JavaScript and bridge state only to later navigation sinks", async () => {
    const result = await findings(`
      final incomingUri = Uri.base.queryParameters['target'];
      final controller = WebViewController();
      controller.loadRequest(Uri.parse(incomingUri!));
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      controller.loadRequest(Uri.parse(incomingUri!));
      controller.addJavaScriptChannel('NativeBridge', onMessageReceived: onMessage);
      controller.loadRequest(Uri.parse(incomingUri!));
    `);

    expect(result.map((finding) => finding.severity)).toEqual(["medium", "high"]);
  });

  test("does not carry same-named controller state across sibling lexical scopes", async () => {
    await expect(findings(`
      void configure() {
        final controller = WebViewController();
        controller.setJavaScriptMode(JavaScriptMode.unrestricted);
        controller.addJavaScriptChannel('NativeBridge', onMessageReceived: onMessage);
      }

      void navigate() {
        final incomingUri = Uri.base.queryParameters['target'];
        final controller = WebViewController();
        controller.loadRequest(Uri.parse(incomingUri!));
      }
    `)).resolves.toHaveLength(0);

    await expect(findings(`
      void navigate() {
        final incomingUri = Uri.base.queryParameters['target'];
        final controller = WebViewController();
        controller.setJavaScriptMode(JavaScriptMode.unrestricted);
        if (incomingUri != null) {
          controller.loadRequest(Uri.parse(incomingUri));
        }
      }
    `)).resolves.toMatchObject([{ severity: "medium" }]);
  });

  test("keeps a trusted constant named deepLink silent", async () => {
    await expect(findings(`
      const deepLink = 'https://trusted.example/content';
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      controller.loadRequest(Uri.parse(deepLink));
    `)).resolves.toHaveLength(0);
  });

  test("retains proven Uri.base, route, callback, and exact allowlist behavior", async () => {
    const proven = await findings(`
      final fromBase = Uri.base;
      final fromRoute = ModalRoute.of(context)!.settings.arguments as Uri;
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      controller.loadRequest(fromBase);
      controller.loadRequest(fromRoute);
      uriLinkStream.listen((incomingUri) {
        controller.loadRequest(incomingUri);
      });
    `);
    expect(proven.map((finding) => finding.severity)).toEqual(["medium", "medium", "medium"]);

    await expect(findings(`
      final candidate = Uri.parse(Uri.base.queryParameters['target']!);
      final controller = WebViewController();
      controller.setJavaScriptMode(JavaScriptMode.unrestricted);
      if (candidate.scheme == 'https' && candidate.host == 'trusted.example') {
        controller.loadRequest(candidate);
      }
    `)).resolves.toHaveLength(0);
  });
});
