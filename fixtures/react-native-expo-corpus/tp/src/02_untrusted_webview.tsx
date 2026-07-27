import { WebView as AppWebView } from "react-native-webview";

export function RedirectScreen({ route }: { route: { params: { redirectUrl: string } } }) {
  const requestedUrl = route.params.redirectUrl;
  return <AppWebView source={{ uri: requestedUrl }} />;
}
