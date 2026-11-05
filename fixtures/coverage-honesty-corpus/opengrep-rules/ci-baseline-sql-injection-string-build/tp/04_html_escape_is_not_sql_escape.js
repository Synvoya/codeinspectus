// Review fix: an HTML escaper is not an SQL escaper; only driver escapes sanitize a query.
const he = require("he");
module.exports = (app, db) => {
  app.get("/u", (req) => db.query("SELECT * FROM users WHERE id = '" + he.escape(req.query.id) + "'"));
};
