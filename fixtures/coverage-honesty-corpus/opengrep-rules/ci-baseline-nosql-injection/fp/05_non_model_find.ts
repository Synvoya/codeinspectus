export async function list(req: any, res: any, repo: any) {
  res.json(await repo.find(req.query));
}
