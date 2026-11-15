declare function listDevices(): Promise<Array<{ id: string; token: string; refreshToken: string; label: string }>>;
declare const currentToken: string;

export async function GET() {
  const devices = await listDevices();
  return Response.json(
    devices.map(({ token, refreshToken, ...device }) => ({ ...device, current: token === currentToken })),
  );
}
