module.exports = (app, knex) => app.get("/t", (req) => knex.raw("SELECT " + req.query.col + " FROM t"));
