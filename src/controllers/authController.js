const User = require('../models/userModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');

const generateAccessToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
const generateRefreshToken = (id) =>
  jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN });

// @route   POST /api/auth/register
// @desc    Register new user
exports.register = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ msg: 'User already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hash, name });
    await user.save();
    res.status(201).json({ msg: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// @route   POST /api/auth/login
// @desc    Authenticate user & get tokens
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: 'Invalid credentials' });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ accessToken, refreshToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// @route   POST /api/auth/refresh
// @desc    Refresh access token
exports.refreshToken = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ msg: 'Refresh token required' });
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || !user.refreshTokens.includes(refreshToken)) {
      return res.status(403).json({ msg: 'Invalid refresh token' });
    }
    const accessToken = generateAccessToken(user._id);
    res.json({ accessToken });
  } catch (err) {
    res.status(403).json({ msg: 'Invalid refresh token' });
  }
};

// @route   POST /api/auth/logout
// @desc    Logout & invalidate refresh token
exports.logout = async (req, res) => {
  const { refreshToken } = req.body;
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);
    if (user) {
      user.refreshTokens = user.refreshTokens.filter(rt => rt !== refreshToken);
      await user.save();
    }
    res.json({ msg: 'Logged out successfully' });
  } catch (err) {
    res.status(400).json({ msg: 'Invalid token' });
  }
};

// @route   POST /api/auth/forgot-password
// @desc    Generate reset token & send via email
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ msg: 'No user with that email' });

  const resetToken = crypto.randomBytes(20).toString('hex');
  user.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 mins
  await user.save({ validateBeforeSave: false });

  const resetUrl = `${req.protocol}://${req.get('host')}/api/auth/reset-password/${resetToken}`;
  const message = `You are receiving this email because you (or someone else) requested a password reset.\n\n` +
                  `Please make a PUT request to: ${resetUrl}`;

  await sendEmail({ email: user.email, subject: 'Password Reset', message });
  res.json({ msg: 'Reset token sent to email' });
};

// @route   POST /api/auth/reset-password/:resetToken
// @desc    Reset password
exports.resetPassword = async (req, res) => {
  const resetToken = req.params.resetToken;
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });
  if (!user) return res.status(400).json({ msg: 'Invalid or expired token' });

  user.password = await bcrypt.hash(req.body.password, 10);
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  res.json({ msg: 'Password has been reset' });
};

// @route   GET /api/auth/me
// @desc    Get current user profile
exports.getMe = async (req, res) => {
  const user = await User.findById(req.user.id).select('-password -refreshTokens');
  res.json(user);
};

// @route   PATCH /api/auth/me
// @desc    Update user profile
exports.updateMe = async (req, res) => {
  const updates = { name: req.body.name, avatar: req.body.avatar };
  if (req.body.password) {
    updates.password = await bcrypt.hash(req.body.password, 10);
  }
  const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-password -refreshTokens');
  res.json(user);
};

