// A placeholder list built from the input's length carries no input into the query text.
module.exports = (app, db) => {
  app.post("/u", (req) => {
    const ids = req.body.ids;
    const placeholders = ids.map(() => "?").join(",");
    return db.query("SELECT * FROM t WHERE id IN (" + placeholders + ")", ids);
  });
};
