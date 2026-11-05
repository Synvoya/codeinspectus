module.exports = (app, db) => app.get("/u", (req) => db.query(`SELECT * FROM users WHERE id = ${req.query.id}`));
