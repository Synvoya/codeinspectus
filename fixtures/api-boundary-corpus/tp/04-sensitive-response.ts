declare const user: { id: string; passwordHash: string };
declare const session: { accessToken: string; refreshToken: string };
declare const privateKey: string;
declare const clientSecret: string;
declare const apiKey: string;

export function GET() {
  return Response.json({
    id: user.id,
    password_hash: user.passwordHash,
    access_token: session.accessToken,
    refresh_token: session.refreshToken,
    api_key: apiKey,
    client_secret: clientSecret,
    private_key: privateKey,
  });
}
