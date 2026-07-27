import { describe, expect, test } from "vitest";

import type { Finding } from "../../types.js";
import { parseJavaScriptSource } from "./javascript.js";
import type { ReactNativeProject, ReactNativeProjectInput } from "./project.js";
import { createReactNativeAnalyzers } from "./index.js";
import { runReactNativeSensitiveAsyncStorage } from "./async-storage.js";
import { runReactNativeWebViewUntrustedContent } from "./webview-untrusted.js";
import { runReactNativeWebViewMixedContent } from "./webview-mixed-content.js";
import { runReactNativeWebViewUniversalFileAccess } from "./webview-universal-file-access.js";

function project(source: string, path = "src/App.tsx"): ReactNativeProject {
  return {
    target: "/virtual/react-native",
    root: "/virtual/react-native",
    files: [parseJavaScriptSource(path, source)],
  };
}

function findings(
  runner: (input: ReactNativeProjectInput) => Promise<Finding[]>,
  source: string,
): Promise<Finding[]> {
  return runner(project(source));
}

describe("React Native AsyncStorage credential rule", () => {
  test("flags imported receivers, one-hop aliases, legacy imports, and all supported writes", async () => {
    const result = await findings(runReactNativeSensitiveAsyncStorage, `
      import AsyncStorage from '@react-native-async-storage/async-storage';
      import { AsyncStorage as LegacyStorage } from 'react-native';
      const Storage = AsyncStorage;
      await Storage.setItem('access_token', accessToken);
      await AsyncStorage.mergeItem('credentials', JSON.stringify({ password }));
      await LegacyStorage.multiSet([['refresh_token', refreshToken], ['theme', 'dark']]);
    `);
    expect(result).toHaveLength(3);
    expect(result.every((item) =>
      item.rule_id === "ci-react-native-sensitive-async-storage" &&
      item.severity === "high" && item.confidence === "high" &&
      item.cwe[0] === "CWE-312"
    )).toBe(true);
    expect(result.every((item) => !(item.location.snippet ?? "").includes("refreshToken"))).toBe(true);
  });

  test("excludes safe derivatives, status fields, device tokens, empty/boolean values, lookalikes, and secure stores", async () => {
    await expect(findings(runReactNativeSensitiveAsyncStorage, `
      import AsyncStorage from '@react-native-async-storage/async-storage';
      import * as SecureStore from 'expo-secure-store';
      await AsyncStorage.setItem('access_token_hash', hash(accessToken));
      await AsyncStorage.setItem('token_expiry', tokenExpiry);
      await AsyncStorage.setItem('fcm_token', fcmToken);
      await AsyncStorage.setItem('remember_password', false);
      await AsyncStorage.setItem('password', '');
      storage.setItem('access_token', accessToken);
      SecureStore.setItemAsync('access_token', accessToken);
      const text = "AsyncStorage.setItem('password', password)";
      // AsyncStorage.setItem('password', password);
    `)).resolves.toHaveLength(0);
  });

  test("honors shadowing and the one-hop alias bound", async () => {
    await expect(findings(runReactNativeSensitiveAsyncStorage, `
      import AsyncStorage from '@react-native-async-storage/async-storage';
      const First = AsyncStorage;
      const Second = First;
      Second.setItem('access_token', accessToken);
      function save(AsyncStorage: { setItem: Function }) {
        AsyncStorage.setItem('password', password);
      }
    `)).resolves.toHaveLength(0);
  });

  test("does not confuse tokenizer names with tokens and does not suppress credential objects", async () => {
    const tokenizer = await findings(runReactNativeSensitiveAsyncStorage, `
      import AsyncStorage from '@react-native-async-storage/async-storage';
      await AsyncStorage.setItem('tokenizer_model', tokenizerModel);
    `);
    const credentialObject = await findings(runReactNativeSensitiveAsyncStorage, `
      import AsyncStorage from '@react-native-async-storage/async-storage';
      await AsyncStorage.setItem('session', JSON.stringify({ accessToken, status }));
    `);
    expect(tokenizer).toHaveLength(0);
    expect(credentialObject).toHaveLength(1);
  });
});

describe("React Native WebView untrusted-content rule", () => {
  test("flags route input with default JavaScript and raises bridge severity", async () => {
    const medium = await findings(runReactNativeWebViewUntrustedContent, `
      import { WebView as Browser } from 'react-native-webview';
      export const Screen = ({ route }) => {
        const target = route.params.target;
        return <Browser source={{ uri: target }} />;
      };
    `);
    const high = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route }) =>
        <WebView source={{ html: route.params.markup }} onMessage={handleMessage} />;
    `);
    expect(medium).toHaveLength(1);
    expect(medium[0]).toMatchObject({ severity: "medium", cwe: ["CWE-20", "CWE-346"] });
    expect(high).toHaveLength(1);
    expect(high[0]?.severity).toBe("high");
  });

  test("tracks Expo Router search parameters and Linking callback aliases", async () => {
    const expo = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { useLocalSearchParams as useParams } from 'expo-router';
      export function Screen() {
        const params = useParams();
        const page = params.page;
        return <WebView source={{ uri: page }} />;
      }
    `);
    const linking = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { Linking } from 'react-native';
      Linking.addEventListener('url', event => {
        const incoming = event.url;
        render(<WebView source={{ uri: incoming }} />);
      });
    `);
    expect(expo).toHaveLength(1);
    expect(linking).toHaveLength(1);
  });

  test("accepts only an imported React Navigation useRoute hook as route evidence", async () => {
    const result = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { useRoute as useNavigationRoute } from '@react-navigation/native';
      export function Screen() {
        const route = useNavigationRoute();
        return <WebView source={{ uri: route.params.url }} />;
      }
    `);
    expect(result).toHaveLength(1);
  });

  test("tracks typed Linking callbacks and named expo-linking useURL imports", async () => {
    const typed = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { Linking } from 'react-native';
      Linking.addEventListener('url', (event: LinkingEvent) => {
        const incoming = event.url;
        render(<WebView source={{ uri: incoming }} />);
      });
    `);
    const named = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { useURL as useIncomingURL } from 'expo-linking';
      export function Screen() {
        const incoming = useIncomingURL();
        return <WebView source={{ uri: incoming }} />;
      }
    `);
    expect(typed).toHaveLength(1);
    expect(named).toHaveLength(1);
  });

  test("tracks React Native initial URLs, Expo namespace hooks, and function callbacks", async () => {
    const initial = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { Linking } from 'react-native';
      export async function Screen() {
        const incoming = await Linking.getInitialURL();
        return <WebView source={{ uri: incoming }} />;
      }
    `);
    const expoNamespace = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import * as Linking from 'expo-linking';
      export function Screen() {
        const incoming = Linking.useURL();
        return <WebView source={{ uri: incoming }} />;
      }
    `);
    const callback = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { Linking } from 'react-native';
      Linking.addEventListener('url', function(event) {
        const incoming = event.url;
        render(<WebView source={{ uri: incoming }} />);
      });
    `);
    const promised = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import { Linking } from 'react-native';
      Linking.getInitialURL().then(url => render(
        <WebView source={{ uri: url }} />
      ));
    `);
    expect(initial).toHaveLength(1);
    expect(expoNamespace).toHaveLength(1);
    expect(callback).toHaveLength(1);
    expect(promised).toHaveLength(1);
  });

  test("excludes trusted/static, JavaScript-disabled, sanitized, exact-origin-gated, and fixed-policy sources", async () => {
    await expect(findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import DOMPurify from 'dompurify';
      const Static = () => <WebView source={{ uri: 'https://mobile.prod.tld' }} />;
      const Disabled = ({ route }) => <WebView javaScriptEnabled={false} source={{ uri: route.params.url }} />;
      const Sanitized = ({ route }) => <WebView source={{ html: DOMPurify.sanitize(route.params.html) }} />;
      function Guarded({ route }) {
        const parsed = new URL(route.params.url);
        if (parsed.protocol === 'https:' && parsed.hostname === 'mobile.prod.tld') {
          return <WebView source={{ uri: route.params.url }} />;
        }
      }
      const Fixed = ({ route }) => <WebView originWhitelist={['https://mobile.prod.tld']} source={{ uri: route.params.url }} />;
      const Callback = ({ route }) => <WebView
        onShouldStartLoadWithRequest={(request) => {
          const parsed = new URL(request.url);
          return parsed.protocol === 'https:' && parsed.hostname === 'mobile.prod.tld';
        }}
        source={{ uri: route.params.url }}
      />;
      const safeNavigation = (request) => {
        const parsed = new URL(request.url);
        return parsed.protocol === 'https:' && parsed.hostname === 'mobile.prod.tld';
      };
      const NamedCallback = ({ route }) => <WebView
        onShouldStartLoadWithRequest={safeNavigation}
        source={{ uri: route.params.url }}
      />;
      const FunctionCallback = ({ route }) => <WebView
        onShouldStartLoadWithRequest={function(request) {
          const parsed = new URL(request.url);
          return parsed.protocol === 'https:' && parsed.hostname === 'mobile.prod.tld';
        }}
        source={{ uri: route.params.url }}
      />;
    `)).resolves.toHaveLength(0);
  });

  test("fails closed for dynamic JavaScript, JSX spreads, shadowed/lookalike components, and malformed source", async () => {
    await expect(findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      const Dynamic = ({ route, enabled }) => <WebView javaScriptEnabled={enabled} source={{ uri: route.params.url }} />;
      const Spread = ({ route, props }) => <WebView source={{ uri: route.params.url }} {...props} />;
      const Fake = ({ route }) => <View.WebView source={{ uri: route.params.url }} />;
      function Shadow(WebView) { return <WebView source={{ uri: route.params.url }} />; }
    `)).resolves.toHaveLength(0);
    await expect(findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      const Broken = ({ route }) => <WebView source={{ uri: route.params.url };
    `)).resolves.toHaveLength(0);
  });

  test("does not taint unproven route lookalikes or locally defined useRoute calls", async () => {
    await expect(findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      const route = { params: { url: 'https://mobile.production.tld' } };
      function useRoute() { return route; }
      const LocalObject = () => <WebView source={{ uri: route.params.url }} />;
      const LocalHook = () => <WebView source={{ uri: useRoute().params.url }} />;
    `)).resolves.toHaveLength(0);
  });

  test("requires whole-expression sanitization and never applies URL policies to attacker HTML", async () => {
    const nestedSanitizer = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      import DOMPurify from 'dompurify';
      export const Screen = ({ route }) => <WebView
        source={{ html: DOMPurify.sanitize('<b>prefix</b>') + route.params.html }}
      />;
    `);
    const htmlWithUrlPolicy = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route }) => <WebView
        originWhitelist={['https://mobile.production.tld']}
        onShouldStartLoadWithRequest={(request) => {
          const parsed = new URL(request.url);
          return parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld';
        }}
        source={{ html: route.params.html }}
      />;
    `);
    expect(nestedSanitizer).toHaveLength(1);
    expect(htmlWithUrlPolicy).toHaveLength(1);
  });

  test("binds exact URL guards to the source and rejects boolean-bypass predicates", async () => {
    const unrelated = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route }) {
        const unrelated = new URL('https://mobile.production.tld');
        if (unrelated.protocol === 'https:' && unrelated.hostname === 'mobile.production.tld') {
          return <WebView source={{ uri: route.params.url }} />;
        }
      }
    `);
    const bypassGuard = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route }) {
        const parsed = new URL(route.params.url);
        if ((parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld') || true) {
          return <WebView source={{ uri: route.params.url }} />;
        }
      }
    `);
    const bypassCallback = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route }) => <WebView
        onShouldStartLoadWithRequest={(request) => {
          const parsed = new URL(request.url);
          return (parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld') || true;
        }}
        source={{ uri: route.params.url }}
      />;
    `);
    const negated = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route }) {
        const parsed = new URL(route.params.url);
        if (!(parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld')) {
          return <WebView source={{ uri: route.params.url }} />;
        }
      }
    `);
    expect(unrelated).toHaveLength(1);
    expect(bypassGuard).toHaveLength(1);
    expect(bypassCallback).toHaveLength(1);
    expect(negated).toHaveLength(1);
  });

  test("rejects early-return, ternary, nested-reject, and shadowed-URL guard bypasses", async () => {
    const earlyReturn = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route, bypass }) => <WebView
        onShouldStartLoadWithRequest={(request) => {
          if (bypass) return true;
          const parsed = new URL(request.url);
          return parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld';
        }}
        source={{ uri: route.params.url }}
      />;
    `);
    const ternary = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route, bypass }) => <WebView
        onShouldStartLoadWithRequest={(request) => {
          const parsed = new URL(request.url);
          return bypass ? true : parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld';
        }}
        source={{ uri: route.params.url }}
      />;
    `);
    const comma = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route }) => <WebView
        onShouldStartLoadWithRequest={(request) => {
          const parsed = new URL(request.url);
          return (parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld', true);
        }}
        source={{ uri: route.params.url }}
      />;
    `);
    const nestedReject = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route, debug }) {
        const parsed = new URL(route.params.url);
        if (debug) {
          if (parsed.protocol !== 'https:' || parsed.hostname !== 'mobile.production.tld') return null;
        }
        return <WebView source={{ uri: route.params.url }} />;
      }
    `);
    const unbracedNestedReject = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route, debug }) {
        const parsed = new URL(route.params.url);
        if (debug) if (parsed.protocol !== 'https:' || parsed.hostname !== 'mobile.production.tld') return null;
        return <WebView source={{ uri: route.params.url }} />;
      }
    `);
    const conditionalReject = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route, debug }) {
        const parsed = new URL(route.params.url);
        if (parsed.protocol !== 'https:' || parsed.hostname !== 'mobile.production.tld') {
          if (debug) return null;
        }
        return <WebView source={{ uri: route.params.url }} />;
      }
    `);
    const shadowedUrl = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route }) {
        function URL(value) { return { protocol: 'https:', hostname: 'mobile.production.tld' }; }
        const parsed = new URL(route.params.url);
        if (parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld') {
          return <WebView source={{ uri: route.params.url }} />;
        }
      }
    `);
    const mutatedUrl = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route }) => <WebView
        onShouldStartLoadWithRequest={(request) => {
          const parsed = new URL(request.url);
          parsed.protocol = 'https:';
          parsed.hostname = 'mobile.production.tld';
          return parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld';
        }}
        source={{ uri: route.params.url }}
      />;
    `);
    const mutatedRequest = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route }) => <WebView
        onShouldStartLoadWithRequest={(request) => {
          request.url = 'https://mobile.production.tld';
          const parsed = new URL(request.url);
          return parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld';
        }}
        source={{ uri: route.params.url }}
      />;
    `);
    expect(earlyReturn).toHaveLength(1);
    expect(ternary).toHaveLength(1);
    expect(comma).toHaveLength(1);
    expect(nestedReject).toHaveLength(1);
    expect(unbracedNestedReject).toHaveLength(1);
    expect(conditionalReject).toHaveLength(1);
    expect(shadowedUrl).toHaveLength(1);
    expect(mutatedUrl).toHaveLength(1);
    expect(mutatedRequest).toHaveLength(1);
  });

  test("does not confuse callback member names with a separately bound url parameter", async () => {
    const result = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export const Screen = ({ route }) => <WebView
        onShouldStartLoadWithRequest={(url) => {
          const parsed = new URL(config.url);
          return parsed.protocol === 'https:' && parsed.hostname === 'mobile.production.tld';
        }}
        source={{ uri: route.params.url }}
      />;
    `);
    expect(result).toHaveLength(1);
  });

  test("fails closed when imported WebView is shadowed by hoisting or a method parameter", async () => {
    await expect(findings(runReactNativeWebViewUntrustedContent, `
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
    `)).resolves.toHaveLength(0);
  });

  test("evaluates captured source properties at object construction time", async () => {
    const capturedUntrusted = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route }) {
        let target = route.params.url;
        const source = { uri: target };
        target = 'https://mobile.production.tld';
        return <WebView source={source} />;
      }
    `);
    const capturedTrusted = await findings(runReactNativeWebViewUntrustedContent, `
      import WebView from 'react-native-webview';
      export function Screen({ route }) {
        let target = 'https://mobile.production.tld';
        const source = { uri: target };
        target = route.params.url;
        return <WebView source={source} />;
      }
    `);
    expect(capturedUntrusted).toHaveLength(1);
    expect(capturedTrusted).toHaveLength(0);
  });
});

describe("React Native WebView mixed-content rule", () => {
  test("flags only literal always mode on a proven production HTTPS source", async () => {
    const result = await findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const PROD = 'https://mobile.production.tld/app';
      const source = { uri: PROD };
      export const App = () => <WebView mixedContentMode="always" source={source} />;
    `);
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ severity: "medium", cwe: ["CWE-319"] });
  });

  test("excludes secure/dynamic modes, reserved hosts, dynamic/spread sources, and lookalikes", async () => {
    await expect(findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const mode = 'always';
      const Aliased = () => <WebView mixedContentMode={mode} source={{ uri: 'https://mobile.production.tld' }} />;
      const Dynamic = () => <WebView mixedContentMode={getMode()} source={{ uri: 'https://mobile.production.tld' }} />;
      const Never = () => <WebView mixedContentMode="never" source={{ uri: 'https://mobile.production.tld' }} />;
      const Compat = () => <WebView mixedContentMode="compatibility" source={{ uri: 'https://mobile.production.tld' }} />;
      const Example = () => <WebView mixedContentMode="always" source={{ uri: 'https://api.example.com' }} />;
      const Local = () => <WebView mixedContentMode="always" source={{ uri: 'https://localhost' }} />;
      const Spread = (props) => <WebView mixedContentMode="always" source={{ uri: 'https://mobile.production.tld' }} {...props} />;
      const Fake = () => <FakeWebView mixedContentMode="always" source={{ uri: 'https://mobile.production.tld' }} />;
    `)).resolves.toHaveLength(0);
  });

  test("uses the last duplicate source property and fails closed on object spreads", async () => {
    await expect(findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const Duplicate = () => <WebView mixedContentMode="always" source={{
        uri: 'https://mobile.production.tld',
        uri: 'https://localhost',
      }} />;
      const Spread = ({ safe }) => <WebView mixedContentMode="always" source={{
        uri: 'https://mobile.production.tld',
        ...safe,
      }} />;
    `)).resolves.toHaveLength(0);
  });

  test("uses the last visible source-object member assignment", async () => {
    const safeMutation = await findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const source = { uri: 'https://mobile.production.tld' };
      source.uri = 'https://localhost';
      export const App = () => <WebView mixedContentMode="always" source={source} />;
    `);
    const unsafeMutation = await findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const source = { uri: 'https://localhost' };
      source.uri = 'https://mobile.production.tld';
      export const App = () => <WebView mixedContentMode="always" source={source} />;
    `);
    expect(safeMutation).toHaveLength(0);
    expect(unsafeMutation).toHaveLength(1);
  });

  test("supports semicolonless type imports and declaration chains", async () => {
    const result = await findings(runReactNativeWebViewMixedContent, [
      "import type { ViewStyle } from 'react-native'",
      "import WebView from 'react-native-webview'",
      "const PROD = 'https://mobile.production.tld'",
      "const source = { uri: PROD }",
      "export const App = () => <WebView mixedContentMode=\"always\" source={source} />",
    ].join("\n"));
    expect(result).toHaveLength(1);
  });

  test("ends semicolonless source declarations before call and assignment statements", async () => {
    const call = await findings(runReactNativeWebViewMixedContent, [
      "import WebView from 'react-native-webview'",
      "const PROD = 'https://mobile.production.tld'",
      "const source = { uri: PROD }",
      "render(<WebView mixedContentMode=\"always\" source={source} />)",
    ].join("\n"));
    const assignment = await findings(runReactNativeWebViewMixedContent, [
      "import WebView from 'react-native-webview'",
      "const PROD = 'https://mobile.production.tld'",
      "const source = { uri: PROD }",
      "view = <WebView mixedContentMode=\"always\" source={source} />",
    ].join("\n"));
    expect(call).toHaveLength(1);
    expect(assignment).toHaveLength(1);
  });

  test("fails closed for computed, Object.assign, and conditional source mutations", async () => {
    const computed = await findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const source = { uri: 'https://mobile.production.tld' };
      source['uri'] = 'https://localhost';
      render(<WebView mixedContentMode="always" source={source} />);
    `);
    const assigned = await findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const source = { uri: 'https://mobile.production.tld' };
      Object.assign(source, { uri: 'https://localhost' });
      render(<WebView mixedContentMode="always" source={source} />);
    `);
    const conditional = await findings(runReactNativeWebViewMixedContent, `
      import WebView from 'react-native-webview';
      const source = { uri: 'https://localhost' };
      if (debug) source.uri = 'https://mobile.production.tld';
      render(<WebView mixedContentMode="always" source={source} />);
    `);
    expect(computed).toHaveLength(0);
    expect(assigned).toHaveLength(0);
    expect(conditional).toHaveLength(0);
  });

  test("fails closed for deletion, reflective writes, aliases, and compound source mutations", async () => {
    const mutations = [
      "delete source.uri;",
      "Object.defineProperty(source, 'uri', { value: 'https://localhost' });",
      "Reflect.set(source, 'uri', 'https://localhost');",
      "const alias = source; alias.uri = 'https://localhost';",
      "source.uri &&= 'https://localhost';",
    ];
    for (const mutation of mutations) {
      const result = await findings(runReactNativeWebViewMixedContent, `
        import WebView from 'react-native-webview';
        const source = { uri: 'https://mobile.production.tld' };
        ${mutation}
        render(<WebView mixedContentMode="always" source={source} />);
      `);
      expect(result, mutation).toHaveLength(0);
    }
  });

  test("excludes CGNAT, benchmark, multicast, mapped-private, and IPv6 multicast hosts", async () => {
    const urls = [
      "https://100.64.0.1",
      "https://198.18.0.1",
      "https://224.0.0.1",
      "https://[::ffff:192.168.1.1]",
      "https://[::192.168.1.1]",
      "https://[ff02::1]",
    ];
    const source = `
      import WebView from 'react-native-webview';
      ${urls.map((url, index) =>
        `const View${index} = () => <WebView mixedContentMode="always" source={{ uri: '${url}' }} />;`
      ).join("\n")}
    `;
    await expect(findings(runReactNativeWebViewMixedContent, source)).resolves.toHaveLength(0);
  });
});

describe("React Native WebView universal file-access rule", () => {
  test("flags literal universal access on file-backed JavaScript-enabled content", async () => {
    const direct = await findings(runReactNativeWebViewUniversalFileAccess, `
      import WebView from 'react-native-webview';
      export const App = () => <WebView allowUniversalAccessFromFileURLs={true} source={{ uri: 'file:///android_asset/index.html' }} />;
    `);
    const base = await findings(runReactNativeWebViewUniversalFileAccess, `
      import { WebView as Browser } from 'react-native-webview';
      const ROOT = 'file:///android_asset/';
      export const App = () => <Browser allowUniversalAccessFromFileURLs source={{ html: '<h1>App</h1>', baseUrl: ROOT }} />;
    `);
    expect(direct).toHaveLength(1);
    expect(base).toHaveLength(1);
    expect(direct[0]).toMatchObject({ severity: "high", cwe: ["CWE-200", "CWE-942"] });
  });

  test("excludes false/dynamic, JavaScript-disabled, remote, similarly named, spread, and lookalike cases", async () => {
    await expect(findings(runReactNativeWebViewUniversalFileAccess, `
      import WebView from 'react-native-webview';
      const False = () => <WebView allowUniversalAccessFromFileURLs={false} source={{ uri: 'file:///app/index.html' }} />;
      const Dynamic = ({ allow }) => <WebView allowUniversalAccessFromFileURLs={allow} source={{ uri: 'file:///app/index.html' }} />;
      const Disabled = () => <WebView javaScriptEnabled={false} allowUniversalAccessFromFileURLs source={{ uri: 'file:///app/index.html' }} />;
      const Remote = () => <WebView allowUniversalAccessFromFileURLs source={{ uri: 'https://mobile.production.tld' }} />;
      const OtherProp = () => <WebView allowFileAccessFromFileURLs source={{ uri: 'file:///app/index.html' }} />;
      const Spread = (props) => <WebView {...props} allowUniversalAccessFromFileURLs source={{ uri: 'file:///app/index.html' }} />;
      const Fake = () => <FakeWebView allowUniversalAccessFromFileURLs source={{ uri: 'file:///app/index.html' }} />;
    `)).resolves.toHaveLength(0);
  });

  test("does not treat a top-level baseUrl as file-backed WebView source evidence", async () => {
    await expect(findings(runReactNativeWebViewUniversalFileAccess, `
      import WebView from 'react-native-webview';
      export const App = () => <WebView
        allowUniversalAccessFromFileURLs
        baseUrl="file:///android_asset/"
      />;
    `)).resolves.toHaveLength(0);
  });
});

describe("React Native pack analyzers", () => {
  test("registers four independent, globally prefixed analyzer contracts", () => {
    const analyzers = createReactNativeAnalyzers("/virtual/react-native");
    expect(analyzers.map((analyzer) => analyzer.id)).toEqual([
      "react-native-sensitive-async-storage",
      "react-native-webview-untrusted-content",
      "react-native-webview-mixed-content",
      "react-native-webview-universal-file-access",
    ]);
    expect(new Set(analyzers.flatMap((analyzer) => analyzer.ruleIds)).size).toBe(4);
    expect(analyzers.every((analyzer) =>
      analyzer.components.includes("pack:react-native:dispatch") &&
      analyzer.components.includes("react-native:javascript-structural-parser")
    )).toBe(true);
  });

  test("keeps a 2,000-WebView source file within the structural-analysis time bound", async () => {
    const views = Array.from({ length: 2_000 }, (_value, index) =>
      `<WebView key={${index}} mixedContentMode="always" source={{ uri: 'https://mobile.production.tld/${index}' }} />`
    ).join("\n");
    const source = `
      import WebView from 'react-native-webview';
      export const App = () => <>${views}</>;
    `;
    const started = performance.now();
    const result = await findings(runReactNativeWebViewMixedContent, source);
    const elapsed = performance.now() - started;
    expect(result).toHaveLength(2_000);
    expect(elapsed).toBeLessThan(2_000);
  }, 10_000);
});
