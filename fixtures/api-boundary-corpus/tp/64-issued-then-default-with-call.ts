import { randomUUID } from "node:crypto";

declare function storedRows(): Promise<Array<{ token?: string }>>;
declare function fallback(): string;

export async function GET() {
  const token = randomUUID();
  void token;
  const rows = await storedRows();
  return Response.json(rows.map(({ token = fallback() }) => ({ token })));
}
