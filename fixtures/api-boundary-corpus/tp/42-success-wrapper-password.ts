declare function success<T>(body: T): T;
declare function readGeneratedPassword(request: Request): Promise<string>;

export async function GET(request: Request) {
  const password = await readGeneratedPassword(request);
  return Response.json(success({ password }));
}
