async function handler(_req: unknown, res: any) {
  return res.status(200).json(await loadAdminReport());
}

export default companyAdminBoundary(handler);
