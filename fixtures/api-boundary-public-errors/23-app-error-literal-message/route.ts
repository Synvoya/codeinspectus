import { ArchiveLockedError, SlugTakenError, TemplatesUnavailableError } from "./errors";
import { lockArchive, loadTemplates, reserveSlug } from "./service";

export async function GET() {
  try {
    return Response.json({ templates: await loadTemplates(false) });
  } catch (err) {
    if (err instanceof TemplatesUnavailableError) return Response.json({ error: err.message }, { status: 503 });
    return Response.json({ error: "Could not load templates" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    await reserveSlug(String((await request.json()).slug), new Set());
    return Response.json({ ok: true });
  } catch (error) {
    if (error instanceof SlugTakenError) {
      return Response.json({ error: error.message }, { status: 409 });
    }
    return Response.json({ error: "Could not reserve the address" }, { status: 500 });
  }
}

export async function DELETE() {
  try {
    lockArchive(true);
    return Response.json({ ok: true });
  } catch (failure) {
    if (failure instanceof ArchiveLockedError) return Response.json({ error: failure.message }, { status: 423 });
    return Response.json({ error: "Could not lock the archive" }, { status: 500 });
  }
}
