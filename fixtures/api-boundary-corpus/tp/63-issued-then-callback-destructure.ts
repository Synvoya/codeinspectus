import { randomUUID } from "node:crypto";

declare function storedRows(): Promise<Array<{ token: string }>>;

export async function GET() {
  const token = randomUUID();
  void token;
  const rows = await storedRows();
  return Response.json(rows.map((row) => { const { token } = row; return { token }; }));
}
