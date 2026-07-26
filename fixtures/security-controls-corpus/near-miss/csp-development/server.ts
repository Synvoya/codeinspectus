if (process.env.NODE_ENV === "development") {
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          scriptSrc: ["'self'", "'unsafe-eval'"],
        },
      },
    }),
  );
}
