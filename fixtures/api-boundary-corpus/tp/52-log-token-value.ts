export function onLogin(token: { value: string; expiresAt: Date }) {
  console.log(`issued ${token.value}`);
}
