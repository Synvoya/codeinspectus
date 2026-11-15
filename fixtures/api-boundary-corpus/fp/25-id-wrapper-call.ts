declare function makeId(input: { password: string }): string;
declare function readPassword(request: Request): Promise<string>;

export async function POST(request: Request) {
  const password = await readPassword(request);
  // The password only seeds an opaque id; the response carries the id.
  return Response.json({
    userId: makeId({
      password,
    }),
  });
}
