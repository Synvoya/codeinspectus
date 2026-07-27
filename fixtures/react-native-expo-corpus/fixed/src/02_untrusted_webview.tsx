import { WebView as AppWebView } from "react-native-webview";

export function RedirectScreen({ route }: { route: { params: { redirectUrl: string } } }) {
  return <AppWebView source={{ uri: route.params.redirectUrl }} javaScriptEnabled={false} />;
}
