// Known gap (4.1, M7 Ruling H): the whole request body passed to findOneAndUpdate is not reported. The 4.1 recall arm for it cost
// main-pass time with no hit on the fresh set, so it moved to 4.2; this file records the shape.
const Account = require("./models/account");
exports.patch = async (req, res) => {
  res.json(await Account.findOneAndUpdate({ _id: req.user.id }, req.body, { new: true }));
};
