import Link from "next/link";

export default function Page({ id }: { id: string }) {
  return (
    <main className="mx-auto flex max-w-md flex-col">
      <p>Don't have an account? (it's free)</p>
      {id && <span>home</span>}/
      /
      <Link href={`/signup/${id}`}>Sign up: it's quick</Link>
    </main>
  );
}
