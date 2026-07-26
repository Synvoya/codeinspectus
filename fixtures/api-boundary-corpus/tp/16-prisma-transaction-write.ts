export async function handler(req: any, tx: any) {
  return tx.user.update({ where: { id: req.params.id }, data: req.body })
}
