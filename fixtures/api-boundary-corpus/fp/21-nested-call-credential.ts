declare function recordElevation(input: { sessionToken: string; action: string }): Promise<string>;
declare function sessionTokenFrom(request: Request): string;

export async function POST(request: Request) {
  const token = sessionTokenFrom(request);
  return Response.json({
    elevationId: await recordElevation({
      action: "delete-domain",
      sessionToken: token,
    }),
  });
}
