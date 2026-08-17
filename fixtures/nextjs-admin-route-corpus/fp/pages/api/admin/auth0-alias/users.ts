import { withApiAuthRequired as requireApiAuth } from "@auth0/nextjs-auth0";

async function handler(req: any, res: any) {
  if (!req.user.roles.includes("admin")) return res.status(403).end();
  return res.status(200).json(await database.user.findMany());
}

export default requireApiAuth(handler);
