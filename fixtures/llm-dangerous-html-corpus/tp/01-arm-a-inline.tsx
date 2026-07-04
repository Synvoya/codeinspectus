// TP arm A (untrusted -> XSS): a request value rendered as raw HTML inline. Expect: FIRE (high, A03).
export function Bio({ req }: { req: any }) {
  return <div dangerouslySetInnerHTML={{ __html: req.query.bio }} />;
}
