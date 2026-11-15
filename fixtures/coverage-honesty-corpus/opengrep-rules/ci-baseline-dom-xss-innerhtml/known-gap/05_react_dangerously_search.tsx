// Known gap (4.1, M7 Ruling H): React `dangerouslySetInnerHTML` as a sink is not reported. The 4.1 recall arm for it cost
// main-pass time with no hit on the fresh set, so it moved to 4.2; this file records the shape.
// React: the search parameter is written as raw HTML.
export function Banner() {
  const params = new URLSearchParams(location.search);
  const q = params.get("q");
  return <div dangerouslySetInnerHTML={{ __html: q }} />;
}
