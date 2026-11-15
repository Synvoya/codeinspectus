import { ArchiveLockedError, SlugTakenError, TemplatesUnavailableError } from "./errors";

export async function loadTemplates(ready: boolean): Promise<string[]> {
  if (!ready) throw new TemplatesUnavailableError();
  return [];
}

export async function reserveSlug(slug: string, taken: Set<string>): Promise<void> {
  if (taken.has(slug)) throw new SlugTakenError("That address is already taken");
  if (slug.length < 3) throw new SlugTakenError(`Addresses need at least three characters`);
}

export function lockArchive(locked: boolean): void {
  if (locked) throw new ArchiveLockedError("The archive is being exported; try again shortly", 30);
}
