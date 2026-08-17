import { jwtVerify } from "jose";

Deno.serve(async (request) => {
  try {
    const { payload } = await jwtVerify(
      request.headers.get("Authorization") ?? "",
      new Uint8Array(32),
    );
    return Response.json({ subject: payload.sub });
  } catch {
    return new Response("Unauthorized", { status: 401 });
  }
});
