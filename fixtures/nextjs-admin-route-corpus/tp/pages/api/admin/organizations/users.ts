import type { NextApiRequest, NextApiResponse } from "next";

const handler = async (_req: NextApiRequest, res: NextApiResponse) => {
  return res.status(200).json(await database.user.findMany());
};

export default handler;
