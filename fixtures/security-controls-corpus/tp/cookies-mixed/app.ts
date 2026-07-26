response.cookie("session", sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
});

response.cookie("refresh_token", refreshToken, {
  httpOnly: false,
  secure: true,
  sameSite: "strict",
});
