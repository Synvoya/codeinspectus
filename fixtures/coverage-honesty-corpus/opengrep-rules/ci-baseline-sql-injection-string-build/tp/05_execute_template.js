module.exports = (app, conn) => app.delete("/t", (req) => conn.execute(`DELETE FROM t WHERE id = ${req.params.id}`));
