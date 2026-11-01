export function newSession() {
  const sessionKey = Math.random();
  return String(sessionKey);
}
