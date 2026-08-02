// TP component prop: request input crosses one local JSX component prop into __html. Expect: FIRE (A03).
function BioPreview({ html }: { html: string }) {
  return <section dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Page({ req }: { req: any }) {
  return <BioPreview html={req.query.bio} />;
}
