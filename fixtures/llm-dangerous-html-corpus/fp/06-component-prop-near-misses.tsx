// FP component props: trusted literal raw HTML and tainted ordinary text rendering. Expect: SILENT.
function StaticPreview({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

function TextPreview({ text }: { text: string }) {
  return <p>{text}</p>;
}

export function Page({ req }: { req: any }) {
  return <><StaticPreview html="<b>trusted</b>" /><TextPreview text={req.query.bio} /></>;
}
