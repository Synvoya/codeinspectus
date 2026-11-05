const funcster = require("funcster");
const Cryo = require("cryo");
exports.restore = (req, res) => {
  const handlers = funcster.deepDeserialize(JSON.parse(req.body.handlers));
  const state = Cryo.parse(req.cookies.state);
  res.json({ handlers: Object.keys(handlers), state });
};
