import { randomUUID } from "node:crypto";

declare function loadUser(request: Request): Promise<{ id: string; token: string }>;

export async function POST(request: Request) {
  const user = await loadUser(request);
  const token = randomUUID();
  // A later spread wins: the stored user.token replaces the issued one.
  return Response.json({ token, ...user });
}
