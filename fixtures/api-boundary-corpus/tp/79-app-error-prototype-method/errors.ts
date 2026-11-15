export class ShareLimitError extends Error {
  constructor() {
    super("The share limit was reached");
  }
}
