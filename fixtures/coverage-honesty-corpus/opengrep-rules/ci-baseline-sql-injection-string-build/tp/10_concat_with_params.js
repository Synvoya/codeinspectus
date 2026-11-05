exports.search = async (req, res, db) => {
  const rows = await db.query("SELECT * FROM t WHERE name = '" + req.query.name + "' AND org = ?", [req.user.org]);
  res.json(rows);
};
