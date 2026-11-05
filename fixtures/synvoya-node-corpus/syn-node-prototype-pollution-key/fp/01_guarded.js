const settings = {};
const BLOCKED = ["__proto__", "constructor", "prototype"];
exports.update = (req, res) => {
  const { section, key, value } = req.body;
  if (BLOCKED.includes(section)) return res.status(400).end();
  settings[section][key] = value;
  res.json(settings);
};
