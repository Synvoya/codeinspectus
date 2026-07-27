import WebView from "react-native-webview";

export const Generated = () => (
  <WebView
    source={{ uri: "https://generated.acmeapp.com" }}
    mixedContentMode="always"
  />
);
