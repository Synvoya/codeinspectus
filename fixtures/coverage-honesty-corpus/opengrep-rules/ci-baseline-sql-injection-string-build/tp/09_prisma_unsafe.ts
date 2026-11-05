import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function list(req: any, res: any) {
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM posts WHERE tag = '${req.params.tag}'`);
  await prisma.$executeRawUnsafe("DELETE FROM posts WHERE id = " + req.body.id);
  res.json(rows);
}
