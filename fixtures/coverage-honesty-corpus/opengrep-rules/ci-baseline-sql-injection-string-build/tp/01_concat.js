module.exports = (db, id) => db.query("SELECT * FROM users WHERE id = " + id);
