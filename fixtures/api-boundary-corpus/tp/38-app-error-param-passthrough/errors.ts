export class StorageFailureError extends Error {
  constructor(message: string, readonly retryable = false) {
    super(message);
  }
}
