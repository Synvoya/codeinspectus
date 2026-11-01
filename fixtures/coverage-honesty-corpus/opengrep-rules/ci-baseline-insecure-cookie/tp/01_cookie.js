module.exports = (res, value) => res.cookie("sid", value, { httpOnly: false });
