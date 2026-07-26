app.use(
  helmet({
    contentSecurityPolicy: false,
    strictTransportSecurity: false,
  }),
);

response.cookie("session", sessionId, {
  httpOnly: false,
  secure: false,
});
