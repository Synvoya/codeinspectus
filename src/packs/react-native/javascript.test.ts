import { describe, expect, test } from "vitest";

import {
  jsCalls,
  jsxElements,
  lexJavaScript,
  nearestDefinition,
  parseJavaScriptSource,
  resolveImport,
} from "./javascript.js";
import { isReactNativeWebView } from "./analysis.js";

describe("React Native JavaScript structural layer", () => {
  test("keeps comments, strings, templates, and regex bodies atomic", () => {
    const document = parseJavaScriptSource("App.tsx", [
      "",
      "      import WebView from 'react-native-webview';",
      "      const text = '<WebView mixedContentMode=\"always\" />';",
      "      const template = `<WebView allowUniversalAccessFromFileURLs={true} />`;",
      "      const regex = /<WebView source={{uri: route.params.url}} \\/>/;",
      "      // <WebView source={{ uri: route.params.url }} />",
      "      /* AsyncStorage.setItem('access_token', token); */",
      "      export const App = () => <WebView source={{ uri: 'https://mobile.prod.tld' }} />;",
      "    ",
    ].join("\n"));
    expect(document.balanced).toBe(true);
    expect(jsxElements(document)).toHaveLength(1);
    expect(jsCalls(document).some((call) => call.callee === "setItem")).toBe(false);
  });

  test("never treats exact delimiter bodies or nested templates as structure", () => {
    const source = [
      "import WebView from 'react-native-webview';",
      "const closeBrace = '}';",
      "const openBrace = '{';",
      "const comma = ',';",
      "const closeAngle = '>';",
      "const nested = `outer ${`inner ${'}'}`} tail`;",
      "export const App = ({ route }) => <WebView source={{ uri: route.params.url }} />;",
    ].join("\n");
    const document = parseJavaScriptSource("App.tsx", source);
    expect(document.balanced).toBe(true);
    expect(document.tokens.filter((token) => token.kind === "template")).toHaveLength(1);
    expect(jsxElements(document)).toHaveLength(1);
  });

  test("marks unterminated regex literals malformed instead of tokenizing their body as code", () => {
    const document = parseJavaScriptSource("broken.tsx", [
      "import WebView from 'react-native-webview';",
      "const pattern = /WebView source route params",
    ].join("\n"));
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues).toEqual(expect.arrayContaining([
      expect.stringContaining("Unterminated regular-expression literal"),
    ]));
    expect(jsxElements(document)).toEqual([]);
  });

  test("distinguishes regex literals beginning with equals from division assignment", () => {
    const document = parseJavaScriptSource("valid.ts", [
      'const normalized = parameter.replace(/=.*/s, "").trim();',
      "let total = 8;",
      "total /= 2;",
    ].join("\n"));
    expect(document.balanced).toBe(true);
    expect(document.lexicalIssues).toEqual([]);
    expect(document.tokens.some((token) => token.kind === "regex" && token.value === "/=.*/s")).toBe(true);
    expect(document.tokens.filter((token) => token.value === "/=")).toHaveLength(1);
  });

  test("marks raw-newline quoted strings malformed and never indexes the remaining text", () => {
    const document = parseJavaScriptSource("broken.tsx", [
      "const text = 'unterminated",
      "import WebView from 'react-native-webview';",
      "const App = ({ route }) => <WebView source={{ uri: route.params.url }} />;",
    ].join("\n"));
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues).toEqual(expect.arrayContaining([
      expect.stringContaining("Unterminated quoted string"),
    ]));
    expect(jsxElements(document)).toEqual([]);
  });

  test("enforces the token bound while lexing instead of allocating the full token stream", () => {
    const result = lexJavaScript("x;".repeat(1_000), 20);
    expect(result.tokens).toHaveLength(20);
    expect(result.issues).toEqual([
      "JavaScript/TypeScript token bound exceeded (20).",
    ]);
  });

  test("resolves aliased imports in source order and honors lexical shadowing", () => {
    const document = parseJavaScriptSource("App.tsx", `
      import { WebView as ImportedWebView } from 'react-native-webview';
      const Browser = ImportedWebView;
      const first = <Browser source={{ uri: route.params.url }} />;
      function Local(Browser: unknown) {
        return <Browser source={{ uri: route.params.url }} />;
      }
    `);
    const elements = jsxElements(document);
    expect(elements).toHaveLength(2);
    expect(isReactNativeWebView(document, elements[0]!)).toBe(true);
    expect(isReactNativeWebView(document, elements[1]!)).toBe(false);
    expect(resolveImport(document, ["Browser"], elements[0]!.tokenIndex)?.source).toBe("react-native-webview");
    expect(nearestDefinition(document, "Browser", elements[1]!.tokenIndex)?.origin).toBeUndefined();
  });

  test("resolves bounded static require and destructured-require bindings", () => {
    const document = parseJavaScriptSource("App.cjs", `
      const Module = require('react-native-webview');
      const { WebView: Browser } = require('react-native-webview');
      const first = <Module.WebView source={{ uri: 'https://mobile.production.tld' }} />;
      const second = <Browser source={{ uri: 'https://mobile.production.tld' }} />;
    `);
    const elements = jsxElements(document);
    expect(elements).toHaveLength(2);
    expect(elements.every((element) => isReactNativeWebView(document, element))).toBe(true);
  });

  test("keeps semicolonless imports and declarations in separate statements", () => {
    const document = parseJavaScriptSource("App.tsx", [
      "import type { ViewStyle } from 'react-native'",
      "import WebView from 'react-native-webview'",
      "const source = { uri: 'https://mobile.production.tld' }",
      "export const App = () => <WebView mixedContentMode=\"always\" source={source} />",
    ].join("\n"));
    const element = jsxElements(document)[0]!;
    expect(document.balanced).toBe(true);
    expect(isReactNativeWebView(document, element)).toBe(true);
  });

  test("honors hoisted function and class-method parameter shadowing", () => {
    const document = parseJavaScriptSource("App.tsx", `
      import WebView from 'react-native-webview';
      function Screen() {
        return <WebView source={{ uri: route.params.url }} />;
        function WebView() { return null; }
      }
      class OtherScreen {
        render(WebView: unknown) {
          return <WebView source={{ uri: route.params.url }} />;
        }
      }
    `);
    const elements = jsxElements(document);
    expect(elements).toHaveLength(2);
    expect(elements.every((element) => !isReactNativeWebView(document, element))).toBe(true);
  });

  test("parses static JSX props but marks spreads and dynamic values explicitly", () => {
    const document = parseJavaScriptSource("App.tsx", `
      import WebView from 'react-native-webview';
      const view = <WebView {...props} mixedContentMode={mode} source={{ uri: target }} />;
    `);
    const element = jsxElements(document)[0]!;
    expect(element.hasSpread).toBe(true);
    expect(document.hasDynamicJsxSpread).toBe(true);
    expect(element.props.map((prop) => [prop.name, prop.kind])).toEqual([
      ["...", "spread"],
      ["mixedContentMode", "expression"],
      ["source", "expression"],
    ]);
  });

  test("fails closed on malformed structure", () => {
    const document = parseJavaScriptSource("broken.tsx", `
      import WebView from 'react-native-webview';
      export const App = () => <WebView source={{ uri: route.params.url };
    `);
    expect(document.balanced).toBe(false);
    expect(jsxElements(document)).toEqual([]);
    expect(jsCalls(document)).toEqual([]);
  });

  test("fails closed before indexing adversarial structural nesting", () => {
    const nested = `${"(".repeat(65)}value${")".repeat(65)}`;
    const document = parseJavaScriptSource("deep.tsx", `const value = ${nested};`);
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues).toEqual(expect.arrayContaining([
      expect.stringContaining("structural nesting bound exceeded"),
    ]));
    expect(jsxElements(document)).toEqual([]);
  });
});
