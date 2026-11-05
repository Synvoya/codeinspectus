import { describe, expect, test } from "vitest";

import {
  jsCalls,
  jsxElements,
  nearestDefinition,
  parseJavaScriptSource,
  resolveImport,
} from "./javascript.js";
import { isReactNativeWebView } from "./analysis.js";

const parsedWithEval = (path: string, source: string): boolean => {
  const document = parseJavaScriptSource(path, source);
  return document.balanced && jsCalls(document).some((call) => call.callee === "eval");
};

describe("React Native JavaScript structural layer (parser-backed, design §10.9)", () => {
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
      "const nested = `outer ${`inner ${'x'}`} tail`;",
      "export const App = ({ route }) => <WebView source={{ uri: route.params.url }} />;",
    ].join("\n");
    const document = parseJavaScriptSource("App.tsx", source);
    expect(document.balanced).toBe(true);
    // Ruling 26: the nested template's token joins the stream with the substitution's code.
    expect(document.tokens.filter((token) => token.kind === "template")).toHaveLength(2);
    expect(jsxElements(document)).toHaveLength(1);
    // The parser reads a string holding a closing brace inside a substitution exactly (3.x refused it).
    const braced = parseJavaScriptSource("App.tsx", "const nested = `outer ${`inner ${'}'}`} tail`;");
    expect(braced.balanced).toBe(true);
    expect(braced.tokens.filter((token) => token.kind === "string").map((token) => token.staticValue)).toEqual(["}"]);
  });

  test("marks unterminated regex literals malformed instead of tokenizing their body as code", () => {
    const document = parseJavaScriptSource("broken.tsx", [
      "import WebView from 'react-native-webview';",
      "const pattern = /WebView source route params",
    ].join("\n"));
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues).toEqual([expect.stringContaining("JavaScript/TypeScript parse error")]);
    expect(document.tokens).toEqual([]);
    expect(jsxElements(document)).toEqual([]);
  });

  // Field validation (Sink): a TypeScript non-null assertion before division read as a regex start.
  test("reads `x! / y` in TypeScript as a non-null assertion and division", () => {
    const document = parseJavaScriptSource("globe.ts", [
      "export const rgb = (d: number[]) => [d[0]! / 255, d[1]! / 255, value! / 2, (a)! / 3, 4! / 2];",
      "export const missing = !/x/.test(name) && ok;",
    ].join("\n"));
    expect(document.balanced).toBe(true);
    expect(document.lexicalIssues).toEqual([]);
    expect(document.tokens.filter((token) => token.kind === "regex").map((token) => token.value)).toEqual(["/x/"]);
  });

  // Security reviews: no rule may turn real code into a regex body or hide a sink.
  test.each([
    ["an if condition", "if (ready) !/x/.test(name) && eval(code);"],
    ["a while condition", "while (busy) !/x/.test(name) && eval(code);"],
    ["a for await condition", "async function f() { for await (const x of y) !/x/.test(name) && eval(code); }"],
    ["a block", "{ start(); } !/x/.test(name) && eval(code);"],
    ["else", "if (a) b(); else !/x/.test(name) && eval(code);"],
    ["return", "function f() { return !/x/.test(name) && eval(code); }"],
    ["typeof", "const t = typeof !/x/.test(name) && eval(code);"],
    ["a line break", "const t = value\n!/x/.test(name) && eval(code);"],
  ])("a `!` after %s stays a prefix, so the regex and the sink are both read", (_label, line) => {
    for (const path of ["sink.ts", "sink.js"]) {
      const document = parseJavaScriptSource(path, line);
      expect(document.lexicalIssues).toEqual([]);
      expect(document.tokens.some((token) => token.kind === "regex" && token.value === "/x/")).toBe(true);
      expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
    }
  });

  test("a regex directly after an if condition is read as a regex", () => {
    const document = parseJavaScriptSource("cond.js", "if (ready) /x/.test(name) && eval(code);");
    expect(document.lexicalIssues).toEqual([]);
    expect(document.tokens.some((token) => token.kind === "regex" && token.value === "/x/")).toBe(true);
  });

  test("the non-null assertion is TypeScript syntax only", () => {
    for (const path of ["globe.js", "globe.mjs", "globe.jsx"]) {
      expect(parseJavaScriptSource(path, "const r = value! / 255;").lexicalIssues)
        .toEqual([expect.stringContaining("JavaScript/TypeScript parse error")]);
    }
    for (const path of ["globe.ts", "globe.tsx", "globe.mts", "globe.cts"]) {
      expect(parseJavaScriptSource(path, "const r = value! / 255;").lexicalIssues).toEqual([]);
    }
  });

  // 3.x refused a `/` after `}` (block or object literal?); the parser knows which one it is.
  test("a `/` after a closing brace is read as the parser reads it", () => {
    const afterBlock = parseJavaScriptSource("brace.js", "function f() {}\n/x/.test(name) && eval(code);");
    expect(afterBlock.lexicalIssues).toEqual([]);
    expect(afterBlock.tokens.some((token) => token.kind === "regex" && token.value === "/x/")).toBe(true);
    expect(jsCalls(afterBlock).some((call) => call.callee === "eval")).toBe(true);
    const afterObject = parseJavaScriptSource("brace.js", "const r = {}\n/x/g; eval(code);");
    expect(afterObject.balanced).toBe(true);
    expect(afterObject.tokens.some((token) => token.kind === "regex")).toBe(false);
    expect(jsCalls(afterObject).some((call) => call.callee === "eval")).toBe(true);
  });

  // Security review: keyword spellings used as member or private names are names, not keywords.
  test("member and private names spelled like keywords do not start regexes or conditions", () => {
    const document = parseJavaScriptSource("members.ts", [
      "const a = obj.if(x) / 2;",
      "const b = obj?.while(y) / 3;",
      "class C { #for(v: number) { return v; } m() { return this.#for(1) / 4; } }",
      "const c = obj.return / 5;",
      "const d = obj.typeof / 6;",
      "const e = obj.case! / 7;",
    ].join("\n"));
    expect(document.lexicalIssues).toEqual([]);
    expect(document.tokens.some((token) => token.kind === "regex")).toBe(false);
  });

  test("an unmatched `)` is a parse error", () => {
    const document = parseJavaScriptSource("paren.js", "x) / 2;");
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues).toEqual([expect.stringContaining("JavaScript/TypeScript parse error")]);
  });

  // Security review: the token after a template is decided from the template, not from its last inner token.
  test("a `/` directly after a template literal divides", () => {
    // The last inner token is `yield`, after which a `/` would start a regex.
    const document = parseJavaScriptSource("after.js", "function* g() { const r = `${yield}` / 2; eval(z); }");
    expect(document.lexicalIssues).toEqual([]);
    expect(document.tokens.some((token) => token.kind === "regex")).toBe(false);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });

  // Security review: substitution tokens count toward the one per-file token bound.
  test("substitution tokens count toward one token budget", () => {
    // 300,000 tokens inside one substitution, on lines under the per-line cap.
    const large = `const t = \`\${${("a,".repeat(20_000) + "\n").repeat(8)}a}\`;`;
    const document = parseJavaScriptSource("big.js", large);
    expect(document.balanced).toBe(false);
    expect(document.tokens).toEqual([]);
    expect(document.lexicalIssues).toEqual([expect.stringContaining("token bound exceeded (200000)")]);
    const small = parseJavaScriptSource("small.js", `const s = \`${"${a + b + c} ".repeat(200)}\`;`);
    expect(small.balanced).toBe(true);
    expect(small.tokens.filter((token) => token.kind === "identifier" && token.value !== "const").length).toBe(601);
  });

  // Field validation (umami) and Ruling 26: substitutions are lexed as code and their tokens are kept.
  test("code inside template substitutions is tokenized, nested templates included", () => {
    const document = parseJavaScriptSource("sql.ts", [
      "const quote = (p: string) => `'${p.replace(/'/g, \"\\\\'\")}'`;",
      "const ratio = `${a / b} and ${(c) / 2} and ${d! / 3} and ${i++ / 2} and ${x[0] / 4}`;",
      "const choose = `${flag ? /a'b/.source : x} ${typeof /t/} ${(() => { return /r/.test(s); })()}`;",
      "const hidden = `${eval(first)} ${`${eval(second)}`}`;",
    ].join("\n"));
    expect(document.balanced).toBe(true);
    expect(document.lexicalIssues).toEqual([]);
    expect(jsCalls(document).filter((call) => call.callee === "eval").map((call) => document.tokens[call.openIndex + 1]?.value))
      .toEqual(["first", "second"]);
    expect(document.tokens.filter((token) => token.kind === "regex").map((token) => token.value)).toEqual(["/'/g", "/a'b/", "/t/", "/r/"]);
  });

  // 3.x refused these as ambiguous; the parser reads them exactly and the sink stays visible.
  test("a regex or string in a substitution that holds a backtick or closing brace is read exactly", () => {
    for (const source of [
      "const a = `${s.replace(/`/g, '')}`; eval(x);",
      "const b = `${s.split(/}/)}`; eval(x);",
      "const c = `${s.split(\"}\")}`; eval(x);",
    ]) {
      expect(parsedWithEval("guess.ts", source)).toBe(true);
    }
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
    expect(document.lexicalIssues).toEqual([expect.stringContaining("JavaScript/TypeScript parse error")]);
    expect(jsxElements(document)).toEqual([]);
  });

  // Bounded work: a file that could hold far more tokens than the bound is refused before the parser
  // allocates its token stream (measured: 2 MiB of `;` took ~1 GB of heap when parsed).
  test("refuses a file over the token bound before parsing it", () => {
    const started = Date.now();
    const document = parseJavaScriptSource("a.js", (";".repeat(60_000) + "\n").repeat(33));
    expect(document.balanced).toBe(false);
    expect(document.tokens).toEqual([]);
    expect(document.lexicalIssues).toEqual(["JavaScript/TypeScript token bound exceeded (200000)."]);
    expect(Date.now() - started).toBeLessThan(2_000);
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

  // Field re-test G8a: the 3.x context-free pass read JSX text as code and rejected 9 of 20 repositories'
  // valid components (fixture tsx-apostrophe; dub login page; pterodactyl breadcrumbs). JSX text is text
  // to the parser, so these files parse now.
  test("accepts JSX text holding an apostrophe, a parenthetical or a slash", () => {
    const apostrophe = parseJavaScriptSource("app/page.tsx", "export const Page = () => (<p>Don't have an account?</p>);\n");
    expect(apostrophe.balanced).toBe(true);
    const bareSlash = parseJavaScriptSource("app/page.tsx", "export const Page = () => (\n  <p>\n    /\n  </p>\n);\n");
    expect(bareSlash.balanced).toBe(true);
    const document = parseJavaScriptSource("app/page.tsx", [
      "import Link from 'next/link';",
      "export default function Page({ id }) {",
      "  return (",
      "    <main className=\"flex gap-2\">",
      "      <p>Do not have an account? (it is free)</p>",
      "      {id && <span key={id}>home</span>}/",
      "      <Link href={`/u/${id}`}>Sign up!</Link>",
      "    </main>",
      "  );",
      "}",
    ].join("\n"));
    expect(document.balanced).toBe(true);
    expect(document.lexicalIssues).toEqual([]);
    const link = jsxElements(document).find((element) => element.reference.join(".") === "Link");
    expect(link?.line).toBe(7);
    expect(link?.props.map((prop) => prop.name)).toEqual(["href"]);
  });

  test("maps the parser's JSX tokens to the analyzers' token shape; JSX text is not code", () => {
    const source = "export const Page = () => <main><p>Do not call eval(x)</p><Img alt=\"a\" /></main>;\n";
    const document = parseJavaScriptSource("app/page.tsx", source);
    expect(document.tokens.map((token) => token.value)).toEqual([
      "export", "const", "Page", "=", "(", ")", "=>", "<", "main", ">", "<", "p", ">", "</", "p", ">",
      "<", "Img", "alt", "=", "\"a\"", "/>", "</", "main", ">", ";",
    ]);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(false);
    // A type argument is never a JSX element.
    expect(jsxElements(parseJavaScriptSource("a.tsx", "const v = useState<Config>(init);"))).toEqual([]);
  });

  test("never retries TypeScript-only files and fails closed on an unclosed JSX retry", () => {
    const text = "export const page = <p>Don't</p>;\n";
    expect(parseJavaScriptSource("page.ts", text).balanced).toBe(false);
    const typeConfusion = parseJavaScriptSource("types.tsx", "type F = <T>(value: T) => T;\nconst s = 'open;\n");
    expect(typeConfusion.balanced).toBe(false);
    expect(jsxElements(typeConfusion)).toEqual([]);
  });

  // Review I1: a TypeScript `<T>` read as JSX was closed by an unrelated `</Layout>` in a comment, so
  // the retry swallowed `eval(...)` as element text and the packs read `ran`.
  test("a closing tag must name the element it closes", () => {
    // `<T>` before `(` is now read as type parameters, so the reviewer's file parses with eval visible.
    const document = parseJavaScriptSource("page.tsx", [
      "type Render = <T>(value: T) => string;",
      "export const run = eval(location.hash.slice(1));",
      "// rendered inside </Layout>",
      "export const Page = () => <p>Don't panic</p>;",
    ].join("\n"));
    expect(!document.balanced || jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
    expect(parseJavaScriptSource("page.tsx", [
      "const view = ready && <Shell><Wrap>Don't</Wrap>",
      "export const run = 1;",
      "// see </Layout>",
      "</Shell>;",
    ].join("\n")).balanced).toBe(false);
    const matched = parseJavaScriptSource("page.tsx", [
      "export const Page = () => (",
      "  <Layout.Main><svg:g><my-elem>It is fine</my-elem></svg:g><></></Layout.Main>",
      ");",
    ].join("\n"));
    expect(matched.balanced).toBe(true);
  });

  // Security review: a TypeScript generic read as a JSX opening must never turn real code into JSX
  // text and hide a sink. Generic signatures are not JSX, and a retry that loses any call fails closed.
  test.each([
    ["generic arrow", ["const f = <T>(x: T) => eval(x);", "export const Page = () => <p>Don't</p>;"]],
    ["type alias", ["type X = <T>() => void;", "eval(location.hash);", "export const Page = () => <p>Don't</p>;"]],
    ["annotation", ["let run: <T>(v: T) => T;", "eval(location.hash);", "export const Page = () => <p>Don't</p>;"]],
  ])("a TypeScript %s never hides a following eval call", (_label, lines) => {
    const document = parseJavaScriptSource("page.tsx", lines.join("\n"));
    expect(!document.balanced || jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });

  // Security review (3.x JSX retry): code around an element stays visible; text inside an element is
  // JSX text, which never runs, so a call spelled there is not a call.
  test("code around an element stays visible and element text is not code", () => {
    const document = parseJavaScriptSource("page.tsx", [
      "const v = <b>{x}</b>; y = eval(z);",
      "const view = ready && <Panel>",
      "  eval(location.hash);",
      "</Panel>;",
      "a?.(b);",
      "f()(g);",
      "export const Page = () => <p>Don't</p>;",
    ].join("\n"));
    expect(document.balanced).toBe(true);
    const callees = jsCalls(document).map((call) => call.callee);
    expect(callees.filter((callee) => callee === "eval")).toHaveLength(1);
    expect(callees).toContain("f");
    expect(document.tokens.map((token) => token.value)).toEqual(expect.arrayContaining(["y", "=", "?."]));
  });

  test("a JSX attribute string that spans lines is one literal", () => {
    const document = parseJavaScriptSource("Card.jsx", [
      "export const Card = () => (",
      "  <Section",
      "    className=\"rounded-md",
      "      px-4 it's-not-a-quote\"",
      "  >",
      "  </Section>",
      ");",
    ].join("\n"));
    expect(document.balanced).toBe(true);
    const className = jsxElements(document)[0]?.props.find((prop) => prop.name === "className");
    expect(className?.kind).toBe("literal");
    expect(className?.expression.tokens[0]?.staticValue).toBe("rounded-md\n      px-4 it's-not-a-quote");
  });

  // Ruling 30 / review C-1 #1: ECMAScript ends a `//` comment and a hashbang at any line terminator
  // (LF, CR, U+2028, U+2029), not only at LF, so the code after a lone CR runs.
  test.each([
    ["CR", "// note\reval(payload)\n"],
    ["U+2028", "// note eval(payload)\n"],
    ["U+2029", "// note eval(payload)\n"],
    ["CR after a hashbang", "#!/usr/bin/env node\reval(payload)\n"],
    ["U+2028 after a hashbang", "#!/usr/bin/env node eval(payload)\n"],
  ])("a %s ends a single-line comment", (_name, source) => {
    const document = parseJavaScriptSource("a.js", source);
    expect(document.balanced).toBe(true);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });

  // Ruling 30 / review C-1 #6: `.mts` and `.cts` are TypeScript, so the non-null rule applies to them.
  test.each(["a.mts", "a.cts"])("%s is lexed as TypeScript", (path) => {
    const document = parseJavaScriptSource(path, "declare const x: any;\nconst r = x! /2; eval(payload); const z = 1/ 1;\n");
    expect(document.balanced).toBe(true);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });

  // Ruling 30 / review C-1 #7: a script reads Annex B HTML-like comments (`<!--` anywhere, `-->` first on
  // a line or after a block comment that spans lines) as comments; a module does not. The parser applies
  // the rule of the file's goal, so the analyzers see exactly the code Node runs.
  test.each([
    ["<!--", "a.cjs", "<!-- `\neval(payload)\n<!-- `\n"],
    ["--> first on a line", "a.cjs", "--> `\neval(payload)\n--> `\n"],
    ["--> after a block comment", "a.js", "x = 1\n/* c */ --> `\neval(payload)\n--> `\n"],
    ["--> mid-line (a decrement and a comparison)", "a.js", "a --> eval(x)\n"],
  ])("an HTML-like comment (%s) is read with the script rules", (_name, path, source) => {
    expect(parsedWithEval(path, source)).toBe(true);
  });

  test("an HTML-like comment hides only what Node does not run", () => {
    // A block comment holding a CR is a line terminator, so `-->` after it starts a comment in a script.
    const script = parseJavaScriptSource("a.cjs", "x = 1; /* \r */ --> eval(x)\n");
    expect(script.balanced).toBe(true);
    expect(jsCalls(script).some((call) => call.callee === "eval")).toBe(false);
    // A module has no HTML-like comments: `<!--` there is not a comment and this file is invalid.
    expect(parseJavaScriptSource("a.mjs", "x = 1; <!-- eval(x)\n").balanced).toBe(false);
  });

  // Security: a `.js` file runs as a script or, in a `"type": "module"` package, as a module, so no
  // reading the packs accept may hide code the other goal runs.
  // Review (stream D, Critical 1): a `.js`/`.ts`/`.jsx`/`.tsx` file runs as a script or, in a
  // `"type": "module"` package, as a module. Neither reading may be trusted alone: a module reading can
  // open a template that swallows code a script runs, and a script reading can hide code in a comment or
  // string that a module runs. When both are valid and tokenize differently, the file is refused.
  test.each([
    // Reviewer's PoC: as a script line 2 runs (`<!--` starts a comment); as a module a template opens.
    ["an HTML-like comment before a template", "x <!--y; `\neval(payload)\n// `\n"],
    ["an HTML-like comment before code", "x = a <!--y; eval(payload)\n"],
    // As a script `"/ ; eval(payload); //"` is a string; as a module `/2; x = "/` is a regex.
    ["an await identifier", "r = await /2; x = \"/ ; eval(payload); //\"\n"],
  ])("a file whose script and module readings differ by %s is refused", (_name, source) => {
    for (const path of ["a.js", "a.jsx", "a.ts", "a.tsx"]) {
      const document = parseJavaScriptSource(path, source);
      expect(document.balanced).toBe(false);
      expect(document.lexicalIssues).toEqual([expect.stringContaining("reads differently as a script and as a module")]);
    }
  });

  test("an explicit goal has one reading", () => {
    // A `.cjs` file is a script: the HTML-like comment hides line 2 from Node too.
    const script = parseJavaScriptSource("a.cjs", "x <!--y; `\neval(payload)\n// `\n");
    expect(script.balanced).toBe(true);
    expect(jsCalls(script).some((call) => call.callee === "eval")).toBe(true);
    expect(parseJavaScriptSource("a.cjs", "r = await /2; x = \"/ ; eval(payload); //\"\n").balanced).toBe(true);
    // A `.mjs` file is a module. The parser would read `<!--` as operators and open a template over line 2,
    // but V8 rejects an HTML-like comment opener in a module, so the file is refused (re-review R1).
    const module = parseJavaScriptSource("a.mjs", "x <!--y; `\neval(payload)\n// `\n");
    expect(module.balanced).toBe(false);
    expect(module.lexicalIssues).toEqual([expect.stringContaining("HTML-like comment opener")]);
  });

  // Re-review R1: a module reading never treats `<!--` as `<` `!` `--` operators; V8 rejects such a module,
  // so refusing it costs no coverage. This covers files that parse only as modules.
  test.each([
    ["a .mjs module", "a.mjs", "x <!--y;\neval(payload);\n"],
    ["a .mts module", "a.mts", "let x = 1, y = 2;\nx <!--y;\neval(payload);\n"],
    ["a .js file with import syntax", "a.js", "import z from 'z';\nx <!--y;\neval(payload);\n"],
    ["a .ts file whose only ESM syntax is import type", "a.ts", "import type { Z } from 'z';\nx <!--y;\neval(payload);\n"],
    ["a .tsx file with export syntax", "a.tsx", "export const v = 1;\nx <!--y;\neval(payload);\n"],
  ])("%s holding an HTML-like comment opener read as operators is refused", (_name, path, source) => {
    const document = parseJavaScriptSource(path, source);
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues).toEqual([expect.stringContaining("HTML-like comment opener")]);
  });

  test("an HTML-like comment opener spelled inside a string, template, regex or comment is not refused", () => {
    expect(parsedWithEval("a.mjs", "const s = '<!--'; const t = `<!--`; const r = /<!--/; // <!--\neval(payload);\n")).toBe(true);
    expect(parsedWithEval("a.mjs", "const ok = a < !--b;\neval(payload);\n")).toBe(true);
  });

  test("a file valid under one goal only is read under that goal", () => {
    // Module only (import): read as a module.
    expect(parsedWithEval("a.js", "import x from 'x';\nawait x;\neval(payload);\n")).toBe(true);
    // Script only (a sloppy-mode name): read as a script.
    expect(parsedWithEval("a.js", "function protected() {}\neval(payload);\n")).toBe(true);
  });

  test("a decrement compared with > is code", () => {
    expect(parsedWithEval("a.js", "while (n-->0) eval(payload);\n")).toBe(true);
    expect(parsedWithEval("a.js", "while (n-- > 0) eval(payload);\n")).toBe(true);
  });

  // Review I-2: an unterminated regex used to make the 3.x lexer rescan every later `/` (quadratic).
  test("an unterminated regex is a parse error found in linear time", () => {
    const started = Date.now();
    const document = parseJavaScriptSource("a.js", ("(/[".repeat(20_000) + "\n").repeat(30));
    expect(document.balanced).toBe(false);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  // Review I-2 sibling: `x<A<A<A…` made the 3.x tag-end scan quadratic. It is a comparison chain; the
  // parser refuses this depth (fail closed) without a JSX element and within the time bound.
  test("a long comparison chain stays bounded and is never JSX", () => {
    const started = Date.now();
    const document = parseJavaScriptSource("a.jsx", "x" + ("<A".repeat(1_000) + "\n").repeat(99));
    expect(jsxElements(document)).toEqual([]);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  // Security review of 67188f2: the 3.x JSX retry could read `/2); eval(y); (1/` after `</p>` as a
  // regex. The parser reads each file once, exactly: the elements are divided and the sink is visible.
  test.each([
    ["a regex-like slash in JSX text", "a.jsx", "const a = (<p>/[\\]</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
    ["a regex-like slash in TSX text", "a.tsx", "const a = (<p>/[\\]</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
    ["an apostrophe in JSX text", "a.jsx", "const a = (<p>it's</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
    ["a backtick in JSX text", "a.jsx", "const a = (<p>`</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
  ])("%s never hides the code after the element", (_name, path, source) => {
    expect(parsedWithEval(path, source)).toBe(true);
  });

  // Hostile input: nesting far deeper than any real file must not overflow the stack or hang. The
  // parser's recursion error is a parse failure (fail closed), and nothing after it walks recursively.
  test.each([
    ["brackets", ("[".repeat(10_000) + "\n").repeat(10) + ("]".repeat(10_000) + "\n").repeat(10)],
    ["parentheses", ("(".repeat(10_000) + "\n").repeat(10) + "x" + (")".repeat(10_000) + "\n").repeat(10)],
    ["unary operators", ("!".repeat(10_000) + "\n").repeat(10) + "x"],
    ["conditional chains", ("a?b:".repeat(10_000) + "\n").repeat(10) + "c"],
    ["unbraced if chains", ("if(a)".repeat(10_000) + "\n").repeat(10) + "b.c=1;"],
    ["arrow functions", ("()=>".repeat(10_000) + "\n").repeat(10) + "x"],
  ])("100,000-deep %s fail closed without a stack overflow", (_name, source) => {
    const started = Date.now();
    let document: ReturnType<typeof parseJavaScriptSource> | undefined;
    expect(() => { document = parseJavaScriptSource("deep.js", source); }).not.toThrow();
    expect(document?.balanced).toBe(false);
    expect(document?.lexicalIssues.length).toBeGreaterThan(0);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  // Review I-2: native lexing is capped per file (2 MiB characters) and per line (64 KiB), so the
  // worst case stays bounded whatever a later change does; such files are the gap oversized-files.
  test.each([
    ["a line over 64 KiB", "const a = 1;\n" + "x".repeat(64 * 1024 + 1) + "\neval(payload);\n"],
    ["a CR-separated line over 64 KiB", "const a = 1;\r" + "x".repeat(64 * 1024 + 1)],
    ["more than 2 MiB", "a;\n".repeat(700_000)],
  ])("a file with %s is oversized and not lexed", (_name, source) => {
    const document = parseJavaScriptSource("a.js", source);
    expect(document.oversized).toBe(true);
    expect(document.balanced).toBe(false);
    expect(document.tokens).toEqual([]);
  });

  test("a 64 KiB line is still lexed", () => {
    const document = parseJavaScriptSource("a.js", "x".repeat(64 * 1024) + "\neval(payload);\n");
    expect(document.oversized).toBeUndefined();
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });

  // Re-review N-3: the number lexer took any of `[A-Fa-f0-9_xXobOB.eE+-]`, so `1+eval(x)` read as the
  // number `1+e` and the identifier `val`. ECMAScript: an exponent is `e`/`E`, an optional sign and at
  // least one digit, hex digits only follow `0x`; otherwise the number ends.
  test.each([
    ["1+eval(x)", ["1", "+", "eval", "(", "x", ")"]],
    ["2+exec(cmd)", ["2", "+", "exec", "(", "cmd", ")"]],
    ["0x1e+eval(x)", ["0x1e", "+", "eval", "(", "x", ")"]],
    ["1e+5", ["1e+5"]],
    ["1E-3", ["1E-3"]],
    ["1.5e10-x", ["1.5e10", "-", "x"]],
    ["1_000n+0b1010-0o17", ["1_000n", "+", "0b1010", "-", "0o17"]],
    ["1.e5", ["1.e5"]],
    ["1..toString()", ["1.", ".", "toString", "(", ")"]],
  ])("reads %s as ECMAScript numbers", (source, values) => {
    expect(parseJavaScriptSource("a.js", source).tokens.map((token) => token.value)).toEqual(values);
  });

  test("an eval after unspaced arithmetic is a call", () => {
    const document = parseJavaScriptSource("a.js", "const r = 1+eval(payload);\n");
    expect(document.balanced).toBe(true);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });
});

