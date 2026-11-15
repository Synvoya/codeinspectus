import DOMPurify from "dompurify";
// The fragment passes through DOMPurify before it reaches the raw-HTML prop.
export const Preview = () => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(location.hash) }} />;
