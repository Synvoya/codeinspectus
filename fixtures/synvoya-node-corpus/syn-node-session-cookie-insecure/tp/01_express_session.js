const session = require("express-session");
module.exports = (app) => {
  app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: { secure: false, httpOnly: true, maxAge: 86400000 },
  }));
};
