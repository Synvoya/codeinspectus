export function handler() {
  return Response.json(
    { error: "Prisma P2002: unique constraint failed on users_email_key" },
    { status: 500 },
  );
}
