function WebView(_props: unknown) {
  return null;
}

export function Lookalike() {
  return (
    <WebView
      source={{ uri: "file:///tmp/lookalike.html" }}
      mixedContentMode="always"
      allowUniversalAccessFromFileURLs={true}
    />
  );
}
