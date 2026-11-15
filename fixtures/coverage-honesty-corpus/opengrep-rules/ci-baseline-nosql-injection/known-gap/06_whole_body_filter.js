// Known gap (4.1, M7 Ruling H): the whole request body used as the filter is not reported. The 4.1 recall arm for it cost
// main-pass time with no hit on the fresh set, so it moved to 4.2; this file records the shape.
const User = require("./models/user");
exports.search = async (req, res) => {
  res.json(await User.find(req.body));
};
