// packages/auth/src/models/user.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const crypto = require('crypto');
const ApiError = require('../utils/api-error');


const SALT_ROUNDS = Number(process.env.SALT_ROUNDS) || 12;

const refreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  expires: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (v) => validator.isEmail(v),
      message: props => `${props.value} is not a valid email`
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  passwordHistory: [{
    hash: String,
    changedAt: Date
  }],
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  backupCodes: [{
    hash: String,
    used: { type: Boolean, default: false }
  }],
  sessions: [{
    sessionId: String,
    userAgent: String,
    ip: String,
    createdAt: { type: Date, default: Date.now },
    lastActiveAt: { type: Date, default: Date.now }
  }],
  // Account linking: social accounts connected to this user
  linkedAccounts: [{
    provider: { type: String, enum: ['google', 'github', 'facebook'], required: true },
    providerId: { type: String, required: true },
    email: { type: String, required: true },
    linkedAt: { type: Date, default: Date.now }
  }],
  // Device trust: remembered devices that can skip 2FA
  trustedDevices: [{
    deviceId: { type: String, required: true },
    userAgent: String,
    ip: String,
    trustedAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true }
  }],
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String, select: false },
  magicLinkToken: { type: String, select: false },
  magicLinkExpires: { type: Date, select: false },
  passwordResetToken: { type: String, select: false },
  passwordResetExpires: { type: Date, select: false },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, select: false },
  twoFactorSecret: { type: String, select: false },
  twoFactorEnabled: { type: Boolean, default: false },
  // Email OTP login (passwordless one-time codes)
  emailOtpHash: { type: String, select: false },
  emailOtpExpires: { type: Date, select: false },
  emailOtpAttempts: { type: Number, default: 0, select: false },
  // Admin ban management
  isBanned: { type: Boolean, default: false },
  bannedAt: { type: Date },
  bannedReason: { type: String },
  refreshTokens: { type: [refreshTokenSchema], default: [] },
  sessionVersion: { type: Number, default: 0 },
  customFields: { type: mongoose.Schema.Types.Mixed }
}, { timestamps: true });

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ magicLinkToken: 1 });
userSchema.index({ 'refreshTokens.expires': 1 }); // helps queries that prune expired refresh tokens
userSchema.index({ lockUntil: 1 });

// Pre-save: hash password if modified
userSchema.pre('save', async function (next) {
  try {
    if (this.isModified('password')) {
      const salt = await bcrypt.genSalt(SALT_ROUNDS);
      this.password = await bcrypt.hash(this.password, salt);
    }
    // ensure email normalized
    if (this.isModified('email') && this.email) {
      this.email = this.email.toLowerCase().trim();
    }
    next();
  } catch (err) {
    next(err);
  }
});

// Instance methods
userSchema.methods.comparePassword = async function (candidate) {
  if (!this.password) return false;
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.recordPasswordHistory = async function (previousPasswordHash) {
  if (typeof previousPasswordHash !== 'string' || previousPasswordHash.length === 0) {
    throw ApiError.internal('recordPasswordHistory requires previousPasswordHash');
  }

  this.passwordHistory = this.passwordHistory || [];
  this.passwordHistory.push({
    hash: previousPasswordHash,
    changedAt: new Date()
  });

  // Keep last 5 only
  if (this.passwordHistory.length > 5) {
    this.passwordHistory.shift();
  }
};

userSchema.methods.setBackupCodes = async function (codes) {
  this.backupCodes = codes.map(c => ({
    hash: c.hash,
    used: false
  }));
};


userSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// Add a refresh token (returns the token object)
userSchema.methods.addRefreshToken = async function (tokenString, expiresAt) {
  this.refreshTokens = this.refreshTokens || [];
  this.refreshTokens.push({
    token: tokenString,
    expires: expiresAt
  });
  return tokenString;
};

// Revoke a specific refresh token (by token string)
userSchema.methods.revokeRefreshToken = async function (tokenString) {
  this.refreshTokens = (this.refreshTokens || []).filter(t => t.token !== tokenString);
};

// Revoke all refresh tokens (e.g., on password reset)
userSchema.methods.revokeAllRefreshTokens = async function () {
  this.refreshTokens = [];
};

// Remove expired refresh tokens (useful to call periodically or on sensitive flows)
userSchema.methods.pruneExpiredRefreshTokens = async function () {
  const now = Date.now();
  // Use $pull to let DB do the work, avoids race conditions
  await this.model('User').updateOne(
    { _id: this._id },
    { $pull: { refreshTokens: { expires: { $lte: now } } } }
  );
};

// Safe update: apply only allowed fields and save
userSchema.methods.safeUpdate = async function (updates = {}) {
  const forbidden = ['password', 'role', 'refreshTokens', 'isVerified', 'verificationToken', '_id', 'twoFactorSecret'];
  forbidden.forEach(f => delete updates[f]);
  Object.assign(this, updates);
  await this.save();
  return this;
};

//
userSchema.methods.addSession = async function (info) {
  this.sessions.push({
    sessionId: crypto.randomBytes(16).toString('hex'),
    userAgent: info.userAgent,
    ip: info.ip
  });
};

userSchema.methods.revokeSession = async function (sessionId) {
  this.sessions = this.sessions.filter(s => s.sessionId !== sessionId);
};

userSchema.methods.revokeAllSessions = async function () {
  this.sessions = [];
};

//
// ACCOUNT LINKING METHODS
//

// Link a social account to this user
userSchema.methods.linkSocialAccount = async function (provider, providerId, email) {
  this.linkedAccounts = this.linkedAccounts || [];

  // Check if already linked
  const existing = this.linkedAccounts.find(
    a => a.provider === provider && a.providerId === providerId
  );
  if (existing) {
    return existing;
  }

  this.linkedAccounts.push({ provider, providerId, email });
  await this.save();
  return this.linkedAccounts[this.linkedAccounts.length - 1];
};

// Unlink a social account
userSchema.methods.unlinkSocialAccount = async function (provider, providerId) {
  this.linkedAccounts = (this.linkedAccounts || []).filter(
    a => !(a.provider === provider && a.providerId === providerId)
  );
  await this.save();
};

// Check if a social account is already linked
userSchema.methods.hasLinkedAccount = function (provider, providerId) {
  return (this.linkedAccounts || []).some(
    a => a.provider === provider && a.providerId === providerId
  );
};

//
// DEVICE TRUST METHODS
//

// Trust a device (skip 2FA for this device)
userSchema.methods.trustDevice = async function (deviceId, userAgent, ip, ttlDays = 30) {
  this.trustedDevices = this.trustedDevices || [];

  const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);

  // Remove existing entry for same device
  this.trustedDevices = this.trustedDevices.filter(d => d.deviceId !== deviceId);

  this.trustedDevices.push({ deviceId, userAgent, ip, expiresAt });
  await this.save();
};

// Check if a device is trusted
userSchema.methods.isDeviceTrusted = function (deviceId) {
  if (!this.trustedDevices || this.trustedDevices.length === 0) return false;
  const device = this.trustedDevices.find(d => d.deviceId === deviceId);
  if (!device) return false;
  // Check expiry
  return device.expiresAt > new Date();
};

// Revoke trust for a device
userSchema.methods.revokeDeviceTrust = async function (deviceId) {
  this.trustedDevices = (this.trustedDevices || []).filter(d => d.deviceId !== deviceId);
  await this.save();
};

// Revoke all trusted devices
userSchema.methods.revokeAllTrustedDevices = async function () {
  this.trustedDevices = [];
  await this.save();
};

// Verify a backup code using MFA service and mark it as used
userSchema.methods.verifyBackupCode = async function (rawCode, mfaService) {
  if (!mfaService || !this.backupCodes || this.backupCodes.length === 0) {
    return false;
  }

  const match = mfaService.verifyBackupCode(rawCode, this.backupCodes);
  if (!match) {
    return false;
  }

  // Mark the matched code as used and persist
  this.backupCodes = this.backupCodes.map((c) => {
    const codeObj = { ...c };
    if (c.hash === match.hash) {
      codeObj.used = true;
    }
    return codeObj;
  });
  await this.save();
  return true;
};

//
// EMAIL OTP METHODS
//

// Store a hashed OTP with expiry
userSchema.methods.setEmailOtp = async function (hash, ttlMs = 10 * 60 * 1000) {
  this.emailOtpHash = hash;
  this.emailOtpExpires = new Date(Date.now() + ttlMs);
  this.emailOtpAttempts = 0;
  await this.save();
};

// Verify a submitted OTP code (rate-limited attempts, auto-expiry)
userSchema.methods.verifyEmailOtp = async function (rawCode, otpService) {
  if (!otpService || !this.emailOtpHash || !this.emailOtpExpires) return false;

  // Expired
  if (new Date(this.emailOtpExpires) < new Date()) {
    return false;
  }

  // Attempt cap (default 5)
  const maxAttempts = this.emailOtpAttempts >= 5;
  if (maxAttempts) return false;

  const ok = otpService.verifyHash(rawCode, this.emailOtpHash);
  if (!ok) {
    this.emailOtpAttempts = (this.emailOtpAttempts || 0) + 1;
    await this.save();
    return false;
  }

  // Success — consume OTP
  this.emailOtpHash = undefined;
  this.emailOtpExpires = undefined;
  this.emailOtpAttempts = 0;
  await this.save();
  return true;
};

// Clear any pending OTP
userSchema.methods.clearEmailOtp = async function () {
  this.emailOtpHash = undefined;
  this.emailOtpExpires = undefined;
  this.emailOtpAttempts = 0;
  await this.save();
};

//
// ADMIN BAN METHODS
//

// Ban a user
userSchema.methods.ban = async function (reason = '') {
  this.isBanned = true;
  this.bannedAt = new Date();
  this.bannedReason = reason;
  this.refreshTokens = []; // revoke all sessions on ban
  this.sessionVersion = (this.sessionVersion || 0) + 1;
  await this.save();
};

// Unban a user
userSchema.methods.unban = async function () {
  this.isBanned = false;
  this.bannedAt = undefined;
  this.bannedReason = undefined;
  await this.save();
};

// Static helper: find user by refresh token and prune expired ones while returning valid user
userSchema.statics.findByRefreshToken = async function (tokenString) {
  // first prune expired tokens across users (optional heavy op, but targeted query below helps)
  // Then find user that still has this token and which is not expired
  const now = Date.now();
  return this.findOne({
    'refreshTokens.token': tokenString,
    'refreshTokens.expires': { $gt: now }
  }).exec();
};

module.exports = mongoose.model('User', userSchema);
