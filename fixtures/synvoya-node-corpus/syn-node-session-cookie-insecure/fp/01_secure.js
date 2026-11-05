const session = require("express-session");
module.exports = (app) => {
  app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: { secure: process.env.NODE_ENV === "production", httpOnly: true },
  }));
  if (process.env.NODE_ENV !== "production") {
    app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: false } }));
  }
};
