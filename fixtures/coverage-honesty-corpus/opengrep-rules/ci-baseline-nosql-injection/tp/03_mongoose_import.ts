import mongoose from "mongoose";
const accounts = mongoose.model("Account");
export const lookup = (req: any) => accounts.find({ owner: req.body.owner });
