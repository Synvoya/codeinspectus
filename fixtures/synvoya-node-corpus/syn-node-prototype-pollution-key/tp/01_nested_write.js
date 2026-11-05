const settings = {};
exports.update = (req, res) => {
  const { section, key, value } = req.body;
  settings[section][key] = value;
  res.json(settings);
};
