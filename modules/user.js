const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  name: { type: String },
  password: { type: String },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  
});

module.exports = mongoose.model("User", userSchema);