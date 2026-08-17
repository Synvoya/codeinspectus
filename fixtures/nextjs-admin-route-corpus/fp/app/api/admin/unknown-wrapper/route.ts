async function handler() {
  return Response.json(await loadPrivateAdminData());
}

export const GET = secureAdmin(handler);
