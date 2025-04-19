const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String },
  avatar: { type: String },
  refreshTokens: [{ type: String }],
  passwordResetToken: String,
  passwordResetExpires: Date
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
