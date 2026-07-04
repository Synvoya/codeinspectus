// FP constant/trusted: a string literal and a local constant HTML value. Not tainted. Expect: SILENT.
const STATIC_HTML = "<p>Welcome</p>";
export function Static() {
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />
      <footer dangerouslySetInnerHTML={{ __html: STATIC_HTML }} />
    </div>
  );
}
