const mongoose = require("mongoose");
exports.pick = (req, res, items) => {
  // Arrays: find() takes a predicate, and a lowercase receiver proven only by the import is no model.
  const viaPredicate = items.find((item) => item.id === req.body.id);
  const notAModel = items.find(req.body);
  res.json({ viaPredicate, notAModel, connected: mongoose.connection.readyState });
};
