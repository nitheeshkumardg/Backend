const mongoose = require("mongoose");

const sellerSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  name: { type: String },
  password: { type: String },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  
});
const Seller = mongoose.model("Seller", sellerSchema);
module.exports = Seller;