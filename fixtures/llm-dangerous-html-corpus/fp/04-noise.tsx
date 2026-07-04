// FP noise: an untrusted value used in NON-__html positions (title attr, data-* attr) — React escapes
// attributes — plus a constant __html sink. The tainted value never reaches __html. Expect: SILENT.
export function Widget({ req }: { req: any }) {
  const x = req.query.x;
  return (
    <div title={x} data-config={JSON.stringify({ note: x })}>
      <span dangerouslySetInnerHTML={{ __html: "<em>ok</em>" }} />
    </div>
  );
}
