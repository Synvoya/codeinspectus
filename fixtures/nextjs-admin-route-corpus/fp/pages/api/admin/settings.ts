import { getServerSession } from "next-auth";

export default async function handler(_req: unknown, res: any) {
  const session = await getServerSession();
  if (!session?.user) return res.status(401).end();
  if (session.user.role !== "admin") return res.status(403).end();
  return res.status(200).json({ ok: true });
}
