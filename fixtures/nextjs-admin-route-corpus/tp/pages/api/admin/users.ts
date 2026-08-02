import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const users = await database.user.findMany();
  return res.status(200).json(users);
}
