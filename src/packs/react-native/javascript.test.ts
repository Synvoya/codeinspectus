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
      "const nested = `outer ${`inner ${'x'}`} tail`;",
      "export const App = ({ route }) => <WebView source={{ uri: route.params.url }} />;",
    ].join("\n");
    const document = parseJavaScriptSource("App.tsx", source);
    expect(document.balanced).toBe(true);
    // Ruling 26: the nested template's token joins the stream with the substitution's code.
    expect(document.tokens.filter((token) => token.kind === "template")).toHaveLength(2);
    expect(jsxElements(document)).toHaveLength(1);
    // A string holding a closing brace inside a substitution is reported, not trusted.
    expect(parseJavaScriptSource("App.tsx", "const nested = `outer ${`inner ${'}'}`} tail`;").lexicalIssues)
      .toEqual([expect.stringContaining("Ambiguous string in a template substitution")]);
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

  test("the non-null rule applies only to TypeScript files", () => {
    for (const path of ["globe.js", "globe.mjs", "globe.jsx"]) {
      expect(parseJavaScriptSource(path, "const r = value! / 255;").lexicalIssues)
        .toEqual([expect.stringContaining("Unterminated regular-expression literal")]);
    }
    for (const path of ["globe.ts", "globe.tsx", "globe.mts", "globe.cts"]) {
      expect(parseJavaScriptSource(path, "const r = value! / 255;").lexicalIssues).toEqual([]);
    }
  });

  test("a `/` after a closing brace is ambiguous and reported, not guessed", () => {
    const document = parseJavaScriptSource("brace.js", "function f() {}\n/x/.test(name) && eval(code);");
    expect(document.lexicalIssues).toEqual([expect.stringContaining("Ambiguous `/` after a closing brace")]);
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

  test("a `/` after an unmatched `)` is reported, not guessed", () => {
    const document = parseJavaScriptSource("paren.js", "x) / 2;");
    expect(document.lexicalIssues).toEqual(expect.arrayContaining([expect.stringContaining("Ambiguous `/` after an unmatched `)`")]));
  });

  // Security review: the token after a template is decided from the template, not from its last inner token.
  test("a `/` directly after a template literal divides", () => {
    // The last inner token is `yield`, after which a `/` would start a regex.
    const document = parseJavaScriptSource("after.js", "function* g() { const r = `${yield}` / 2; eval(z); }");
    expect(document.lexicalIssues).toEqual([]);
    expect(document.tokens.some((token) => token.kind === "regex")).toBe(false);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });

  // Security review: substitutions share the caller's token budget.
  test("substitution tokens count toward one token budget", () => {
    const source = `const s = \`${"${a + b + c} ".repeat(200)}\`;`;
    const bounded = lexJavaScript(source, 300);
    expect(bounded.issues).toEqual(expect.arrayContaining([expect.stringContaining("token bound exceeded")]));
    expect(bounded.tokens.length).toBeLessThanOrEqual(300);
    expect(lexJavaScript(source, 10_000).issues).toEqual([]);
    // A substitution with 300,000 tokens is merged without spreading it into one call.
    const large = `const t = \`\${${"a+".repeat(150_000)}a}\`;`;
    expect(() => lexJavaScript(large, 1_000_000)).not.toThrow();
    expect(lexJavaScript(large, 1_000_000).tokens.length).toBe(300_006);
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

  test("a regex or string in a substitution that holds a backtick or closing brace is reported, not guessed", () => {
    for (const source of [
      "const a = `${s.replace(/`/g, '')}`; eval(x);",
      "const b = `${s.split(/}/)}`; eval(x);",
      "const c = `${s.split(\"}\")}`; eval(x);",
    ]) {
      const document = parseJavaScriptSource("guess.ts", source);
      expect(document.balanced && document.lexicalIssues.length === 0).toBe(false);
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

  // Field re-test G8a: the context-free pass read JSX text as code and rejected 9 of 20 repositories'
  // valid components (fixture tsx-apostrophe; dub login page; pterodactyl breadcrumbs).
  // Security review of 67188f2: an apostrophe ends the plain pass early (unterminated string), so the
  // retry is refused and such a file stays unparsed (native-parse-errors) until the 4.0 parser.
  test("accepts JSX text holding a parenthetical or a slash after an expression", () => {
    const apostrophe = parseJavaScriptSource("app/page.tsx", "export const Page = () => (<p>Don't have an account?</p>);\n");
    expect(apostrophe.balanced).toBe(false);
    // A lone `/` in JSX text starts an unterminated regex in the plain pass: unparsed as well.
    const bareSlash = parseJavaScriptSource("app/page.tsx", "export const Page = () => (\n  <p>\n    /\n  </p>\n);\n");
    expect(bareSlash.balanced).toBe(false);
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

  test("keeps the exact tokens of a file the context-free pass already accepts", () => {
    const source = "export const Page = () => <main><p>Do not have an account?</p></main>;\n";
    expect(parseJavaScriptSource("app/page.tsx", source).tokens).toEqual(lexJavaScript(source).tokens);
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

  // Security review: the retry may differ from the plain pass only where the plain pass saw a string,
  // template or regex literal, so assignments, optional calls and call chains stay visible.
  test("code inside a misread element stays visible to the analyzers", () => {
    const document = parseJavaScriptSource("page.tsx", [
      "const v = <b>{x}</b>; y = eval(z);",
      "const view = ready && <Panel>",
      "  eval(location.hash);",
      "  a?.(b);",
      "  f()(g);",
      "</Panel>;",
      "export const Page = () => <p>Don't</p>;",
    ].join("\n"));
    if (document.balanced) {
      const callees = jsCalls(document).map((call) => call.callee);
      expect(callees.filter((callee) => callee === "eval")).toHaveLength(2);
      expect(callees).toContain("f");
      expect(document.tokens.map((token) => token.value)).toEqual(expect.arrayContaining(["y", "=", "?."]));
    }
    expect(document.lexicalIssues.length > 0 || document.balanced).toBe(true);
  });

  test("a JSX attribute string that spans lines stays unparsed", () => {
    // Its continuation lines are code to the plain pass; the retry may not reinterpret them.
    const document = parseJavaScriptSource("Card.jsx", [
      "export const Card = () => (",
      "  <section",
      "    className=\"rounded-md",
      "      px-4 it's-not-a-quote\"",
      "  >",
      "  </section>",
      ");",
    ].join("\n"));
    expect(document.balanced).toBe(false);
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

  // Ruling 30 / review C-1 #7: scripts read Annex B HTML-like comments (`<!--` anywhere, `-->` first on
  // a line) as comments; the lexer does not, so either one makes the file unparsed.
  test.each([
    ["<!--", "a.cjs", "<!-- `\neval(payload)\n<!-- `\n"],
    ["--> first on a line", "a.cjs", "--> `\neval(payload)\n--> `\n"],
    ["--> after a block comment", "a.js", "x = 1\n/* c */ --> `\neval(payload)\n--> `\n"],
    // Security review: the decision must not depend on the lexer's line numbers, which count only LF.
    ["--> mid-line", "a.js", "a --> eval(x)\n"],
    ["--> after a block comment holding a CR", "a.js", "x = 1; /* \r */ --> eval(x)\n"],
    ["<!-- mid-line", "a.mjs", "x = 1; <!-- eval(x)\n"],
  ])("an HTML-like comment (%s) is a lexical issue", (_name, path, source) => {
    const document = parseJavaScriptSource(path, source);
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues).toEqual(expect.arrayContaining([expect.stringContaining("HTML-like comment")]));
  });

  test("a decrement compared with > is code only when spaced apart", () => {
    // Any `-->` in code is refused, whatever its position (fail closed).
    expect(parseJavaScriptSource("a.js", "while (n-->0) eval(payload);\n").balanced).toBe(false);
    const document = parseJavaScriptSource("a.js", "while (n-- > 0) eval(payload);\n");
    expect(document.lexicalIssues).toEqual([]);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });

  // Review I-2: an unterminated regex used to resume one character later, so every later `/` on the
  // line rescanned to its end (quadratic: 58 s for a 1 MB line). The file is unparsed either way.
  test("an unterminated regex stops lexing, so a long line stays linear", () => {
    // lexJavaScript has no line cap, so this exercises the lexer itself.
    const started = Date.now();
    const lexed = lexJavaScript("(/[".repeat(350_000));
    expect(lexed.truncated).toBe(true);
    expect(lexed.issues).toEqual(expect.arrayContaining([expect.stringContaining("Unterminated regular-expression literal")]));
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  // Review I-2 sibling: each `<Name` scanned forward for its `>` again, quadratic on `x<A<A<A…`
  // (9.7 s at 128 KB, about 20 s at the 200,000-token bound).
  test("finding JSX tag ends stays linear on many unclosed tags", () => {
    const started = Date.now();
    // Short lines, so the per-line lexing cap does not apply.
    const document = parseJavaScriptSource("a.jsx", "x" + ("<A".repeat(1_000) + "\n").repeat(99));
    expect(document.tokens.length).toBe(198_001);
    expect(jsxElements(document)).toEqual([]);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  // Security review of 67188f2: keepsCode compares only the tokens the plain pass produced. When the
  // plain pass stops early, the JSX retry alone decides the rest of the file, and here it reads
  // `/2); eval(y); (1/` after `</p>` as a regex. A truncated plain pass therefore refuses the retry.
  test.each([
    ["an unterminated regex in JSX text", "a.jsx", "const a = (<p>/[\\]</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
    ["an unterminated regex in TSX text", "a.tsx", "const a = (<p>/[\\]</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
    ["an apostrophe in JSX text", "a.jsx", "const a = (<p>it's</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
    ["a backtick in JSX text", "a.jsx", "const a = (<p>`</p>);\nconst b = (<p>x</p> /2); eval(y); (1/ 1);\n"],
  ])("a plain pass truncated by %s keeps the file unparsed", (_name, path, source) => {
    expect(parseJavaScriptSource(path, source).balanced).toBe(false);
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
  ])("lexes %s as ECMAScript numbers", (source, values) => {
    expect(lexJavaScript(source).tokens.map((token) => token.value)).toEqual(values);
  });

  test("an eval after unspaced arithmetic is a call", () => {
    const document = parseJavaScriptSource("a.js", "const r = 1+eval(payload);\n");
    expect(document.balanced).toBe(true);
    expect(jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });
});

