import { getServerSession } from "next-auth";

export default async (_req: unknown, res: any) => {
  const session = await getServerSession();
  if (!session?.user) return res.status(401).end();
  if (!session.user.permissions.includes("manage_teams")) {
    return res.status(403).end();
  }
  return res.status(200).json(await database.team.findMany());
};
