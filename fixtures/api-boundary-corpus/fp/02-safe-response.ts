declare const user: { id: string; displayName: string };

export function GET() {
  return Response.json({ id: user.id, display_name: user.displayName });
}
