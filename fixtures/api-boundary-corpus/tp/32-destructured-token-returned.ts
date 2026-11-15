declare function listDevices(): Promise<Array<{ id: string; token: string; label: string }>>;

export async function GET() {
  const devices = await listDevices();
  return Response.json(devices.map(({ token, ...device }) => ({ id: device.id, token })));
}
