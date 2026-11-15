class ExportBusyError extends Error {}

async function startExport(): Promise<void> {
  const response = await fetch("https://exports.invalid/start", { method: "POST" });
  if (response.status === 409) {
    const busy = new ExportBusyError("An export is already running");
    busy.message = await response.text();
    throw busy;
  }
}

export async function POST() {
  try {
    await startExport();
    return Response.json({ ok: true });
  } catch (err) {
    if (err instanceof ExportBusyError) return Response.json({ error: err.message }, { status: 409 });
    return Response.json({ error: "Export failed" }, { status: 500 });
  }
}
