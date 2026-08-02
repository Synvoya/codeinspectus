// Fixed component prop: the formerly unsafe request value is sanitized at the call site. Expect: SILENT.
import DOMPurify from "dompurify";

function BioPreview({ html }: { html: string }) {
  return <section dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Page({ req }: { req: any }) {
  return <BioPreview html={DOMPurify.sanitize(req.query.bio)} />;
}
