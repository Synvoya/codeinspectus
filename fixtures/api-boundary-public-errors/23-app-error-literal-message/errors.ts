export class TemplatesUnavailableError extends Error {
  constructor() {
    super("Templates are not available until the migration has run");
    this.name = "TemplatesUnavailableError";
  }
}

export class SlugTakenError extends Error {}

export class ArchiveLockedError extends Error {
  constructor(
    message: string,
    readonly retryAfterSeconds = 60,
  ) {
    super(message);
  }
}
