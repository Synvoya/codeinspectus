import helmet from "helmet";

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        scriptSrc: ["'self'", "'unsafe-eval'"],
      },
    },
  }),
);
