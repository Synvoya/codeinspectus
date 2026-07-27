import WebView from "react-native-webview";

export function LocalDocument() {
  return (
    <WebView
      source={{ uri: "file:///data/user/0/com.acmeapp/files/index.html" }}
      allowUniversalAccessFromFileURLs={true}
    />
  );
}
