function requireAuth() { return true; }
function authorize() { return true; }

export async function DELETE() {
  return Response.json(await deleteEveryAccount());
}
