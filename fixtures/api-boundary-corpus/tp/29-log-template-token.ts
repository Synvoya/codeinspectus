export function onRefresh(session: { refreshToken: string }) {
  const refreshToken = session.refreshToken;
  console.info(`refreshed session with ${refreshToken}`);
}
