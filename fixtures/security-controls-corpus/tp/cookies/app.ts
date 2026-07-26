export function setSessionCookies(response: any) {
  response.cookie("session", "value", {
    httpOnly: false,
    secure: true,
    sameSite: "lax",
  });

  response.cookie("refresh_token", "value", {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  });

  response.cookie("auth_token", "value", {
    httpOnly: true,
    sameSite: "none",
  });
}
