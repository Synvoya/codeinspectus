export async function search(req: any, knex: any) {
  const { name } = req.body;
  return knex.raw(`SELECT * FROM accounts WHERE name = '${name}'`);
}
