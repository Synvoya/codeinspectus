import WebView from "react-native-webview";

export const Example = () => (
  <WebView source={{ uri: "file:///tmp/example.html" }} allowUniversalAccessFromFileURLs={true} />
);
