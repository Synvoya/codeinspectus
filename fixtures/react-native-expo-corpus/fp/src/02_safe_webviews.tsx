import WebView from "react-native-webview";

export function SafeWebViews({ route }: { route: { params: { redirectUrl: string } } }) {
  return (
    <>
      <WebView source={{ uri: route.params.redirectUrl }} javaScriptEnabled={false} />
      <WebView
        source={{ uri: "https://accounts.acmeapp.com" }}
        mixedContentMode="never"
      />
      <WebView
        source={{ uri: "https://docs.acmeapp.com" }}
        allowUniversalAccessFromFileURLs={false}
      />
    </>
  );
}
