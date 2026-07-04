// TP arm A split: an untrusted value pulled to a const, then rendered as raw HTML. Expect: FIRE (taint).
export function Comment({ req }: { req: any }) {
  const bio = req.body.bio;
  return <div className="c" dangerouslySetInnerHTML={{ __html: bio }} />;
}
