import WebView from "react-native-webview";

export function BillingPortal() {
  return (
    <WebView
      source={{ uri: "https://accounts.acmeapp.com" }}
      mixedContentMode="always"
    />
  );
}
