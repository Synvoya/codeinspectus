response.cookie("session", "value", {
  httpOnly: true,
  secure: true,
  sameSite: "none",
});
