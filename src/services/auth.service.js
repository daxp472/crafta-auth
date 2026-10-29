const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { authenticator } = require('otplib');
const crypto = require('crypto');
const User = require('../models/user');
const EmailService = require('../utils/email');
const ApiError = require('../utils/api-error');

class AuthService {
  constructor(config) {
    this.config = config;
    this.emailService = new EmailService(config);
  }

  async logAudit(entry) {
    if (!this.config?.auditService) return;
    try {
      await this.config.auditService.logActivity(entry);
    } catch (_err) {
      // Audit failures should not break auth flows.
    }
  }

  /* ---------------------------------------------
        REGISTER USER
  --------------------------------------------- */
  async register(userData) {
    const user = new User({
      ...userData,
      customFields: this.extractCustomFields(userData)
    });

    const verificationToken = this.generateSecureToken();
    user.verificationToken = verificationToken;

    await user.save();

    if (this.config.emailVerification) {
      await this.emailService.sendVerificationEmail(user, verificationToken);
    }

    return user;
  }

  /* ---------------------------------------------
        VERIFY EMAIL
  --------------------------------------------- */
  async verifyEmail(token) {
    if (!token) {
      throw ApiError.badRequest('Verification token is required');
    }

    const user = await User.findOne({ verificationToken: token }).select('+verificationToken');
    if (!user) {
      throw ApiError.badRequest('Invalid or expired verification token');
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    await this.logAudit({
      userId: user._id,
      action: 'email_verify',
      status: 'success'
    });

    return user;
  }

  /* ---------------------------------------------
        LOGIN USER (WITH ATOMIC LOCKOUT)
  --------------------------------------------- */
  async login(email, password, deviceInfo = {}) {
    const user = await User.findOne({ email });

    if (!user) {
      throw ApiError.invalidCredentials();
    }

    // If locked, do NOT allow login
    const securityAttemptsEnabled = this.config?.features?.securityAttempts !== false;
    if (securityAttemptsEnabled && user.isLocked()) {
      throw ApiError.accountLocked();
    }

    const isValid = await user.comparePassword(password);
    if (!isValid) {
      if (securityAttemptsEnabled) {
        await this.incrementLoginAttempts(user);
      }
      throw ApiError.invalidCredentials();
    }

    // RESET LOCKOUT automatically on correct login
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    // If 2FA is enabled
    const twoFactorEnabled = this.config?.features?.twoFactor !== false;
    if (twoFactorEnabled && user.twoFactorEnabled) {
      const code = authenticator.generate(user.twoFactorSecret);
      await this.emailService.send2FACode(user, code);
      return { requires2FA: true, userId: user._id };
    }

    // Login alert
    if (this.config.loginAlerts) {
      await this.emailService.sendLoginAlert(user, deviceInfo);
    }

    // Regenerate session ID on login if configured
    await this.regenerateSessionIdOnLogin(user);

    const tokens = await this.generateTokens(user);
    return { ...tokens, user };
  }

  /* ---------------------------------------------
        VERIFY 2FA
  --------------------------------------------- */
  async verify2FA(userId, code) {
    const user = await User.findById(userId).select('+twoFactorSecret');

    if (!user) throw ApiError.notFound('User not found');
    if (!user.twoFactorEnabled)
      throw ApiError.badRequest('2FA is not enabled for this user');

    const ok = authenticator.verify({
      token: code,
      secret: user.twoFactorSecret
    });

    // fallback: backup codes
    if (!ok) {
      const backupOK = await user.verifyBackupCode(code, this.config.mfaService);
      if (!backupOK) throw ApiError.twoFactorFailed();
    }


    const tokens = await this.generateTokens(user);
    return { ...tokens, user };
  }

  /* ---------------------------------------------
        REFRESH TOKEN (SECURE)
  --------------------------------------------- */
  async refreshToken(refreshToken) {
    // find only valid (non-expired) tokens
    const user = await User.findByRefreshToken(refreshToken);

    if (!user) throw ApiError.invalidToken();

    // Refresh token rotation (best practice)
    user.revokeRefreshToken(refreshToken);
    await user.save();

    const tokens = await this.generateTokens(user);
    await this.logAudit({
      userId: user._id,
      action: 'refresh_token',
      status: 'success'
    });
    return { ...tokens, user };
  }

  /* ---------------------------------------------
        FORGOT PASSWORD
  --------------------------------------------- */
  async forgotPassword(email) {
    const user = await User.findOne({ email });

    if (!user) {
      // DO NOT reveal user existence
      return;
    }

    const token = this.generateSecureToken();
    user.passwordResetToken = token;
    user.passwordResetExpires = Date.now() + 60 * 60 * 1000; // 1h

    await user.save();
    await this.emailService.sendPasswordResetEmail(user, token);

    return true;
  }

  /* ---------------------------------------------
        RESET PASSWORD
  --------------------------------------------- */
  async resetPassword(token, newPassword) {
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) throw ApiError.badRequest('Invalid or expired reset token');

    // check password history (sequential, short-circuits on first match)
    for (const old of (user.passwordHistory || [])) {
      if (await bcrypt.compare(newPassword, old.hash)) {
        throw ApiError.passwordReuse('Cannot reuse previous passwords');
      }
    }

    const previousPasswordHash = user.password;
    user.password = newPassword;

    await user.recordPasswordHistory(previousPasswordHash);
    user.revokeAllRefreshTokens(); // session invalidate
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await this.logAudit({
      userId: user._id,
      action: 'password_reset',
      status: 'success'
    });

    await user.save();
    return user;
  }

  /* ---------------------------------------------
        GENERATE BACKUP CODES
  --------------------------------------------- */
  async generateBackupCodes(userId, mfaService) {
    const user = await User.findById(userId);
    if (!user) throw ApiError.notFound();

    const codes = mfaService.generateBackupCodes();

    await user.setBackupCodes(codes.map(c => ({ hash: c.hash })));
    await user.save();

    await this.logAudit({
      userId,
      action: 'backup_codes_generated',
      status: 'success'
    });

    return codes.map(c => c.raw); // show only once
  }



  /* ---------------------------------------------
        UPDATE PROFILE (SAFE)
  --------------------------------------------- */
  async updateProfile(userId, updates) {
    const user = await User.findById(userId);
    if (!user) throw ApiError.notFound();

    await user.safeUpdate(updates);
    await this.logAudit({
      userId: user._id,
      action: 'profile_update',
      status: 'success'
    });

    return user;
  }

  /* ---------------------------------------------
        GENERATE ACCESS + REFRESH TOKEN (ROTATION)
  --------------------------------------------- */
  async generateTokens(user) {
    const accessToken = jwt.sign(
      {
        id: user._id,
        email: user.email,
        role: user.role,
        sessionVersion: user.sessionVersion || 0
      },
      this.config.env.JWT_SECRET,
      { expiresIn: this.config.accessTokenExpiry || '1h' }
    );

    const refreshToken = this.generateSecureToken();
    const expiresAt =
      Date.now() +
      (this.config.refreshTokenDays || 7) * 24 * 60 * 60 * 1000;

    user.addRefreshToken(refreshToken, expiresAt);
    await user.save();

    // prune expired refresh tokens in background
    await user.pruneExpiredRefreshTokens();

    return { accessToken, refreshToken };
  }

  /* ---------------------------------------------
        SECURE RANDOM TOKEN
  --------------------------------------------- */
  generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  /* ---------------------------------------------
        ATOMIC LOGIN ATTEMPT INCREMENT
  --------------------------------------------- */
  async incrementLoginAttempts(user) {
    if (this.config?.features?.securityAttempts === false) {
      return;
    }

    const MAX = this.config.maxLoginAttempts || 5;
    const now = Date.now();
    const lockUntil = now + 60 * 60 * 1000;

    // Perform atomic increment in DB to prevent concurrent race conditions
    const updatedUser = await User.findOneAndUpdate(
      { _id: user._id },
      { $inc: { loginAttempts: 1 } },
      { new: true }
    );

    if (updatedUser && updatedUser.loginAttempts >= MAX) {
      updatedUser.lockUntil = lockUntil;
      await updatedUser.save();
      await this.emailService.sendAccountLockEmail(updatedUser);
      await this.logAudit({
        userId: updatedUser._id,
        action: 'account_locked',
        status: 'success'
      });
    }

    // Sync local user instance state
    user.loginAttempts = updatedUser ? updatedUser.loginAttempts : (user.loginAttempts + 1);
    if (user.loginAttempts >= MAX) {
      user.lockUntil = lockUntil;
    }
  }

  /* ---------------------------------------------
        LOGOUT
  --------------------------------------------- */
  async logout(userId, sessionId, refreshToken = null) {
    const user = await User.findById(userId);
    if (!user) throw ApiError.notFound();

    await user.revokeSession(sessionId);
    // Also revoke the refresh token so it cannot be reused
    if (refreshToken) {
      await user.revokeRefreshToken(refreshToken);
    }
    await user.save();

    await this.logAudit({
      userId,
      action: 'logout',
      status: 'success'
    });

    return true;
  }

  async handleSocialLogin(provider, profile) {
    if (!profile) {
      throw ApiError.badRequest('Social profile is required');
    }

    const primaryEmail = profile.emails?.[0]?.value;
    if (!primaryEmail) {
      throw ApiError.badRequest('Social provider did not return an email');
    }

    let user = await User.findOne({ email: primaryEmail });

    if (!user) {
      user = new User({
        email: primaryEmail,
        password: this.generateSecureToken(),
        isVerified: true,
        customFields: {
          socialProvider: provider,
          socialId: profile.id,
          name: profile.displayName
        }
      });
      await user.save();
    } else {
      user.customFields = {
        ...(user.customFields || {}),
        socialProvider: provider,
        socialId: profile.id
      };
      if (profile.displayName) {
        user.customFields.name = profile.displayName;
      }
      await user.save();
    }

    return user;
  }

  /* ---------------------------------------------
        REGENERATE SESSION ID ON LOGIN
  --------------------------------------------- */
  async regenerateSessionIdOnLogin(user) {
    // Opt-in only — bumping sessionVersion on every login invalidates all
    // existing sessions, which breaks normal multi-session usage.
    if (this.config?.session?.regenerateSessionIdOnLogin === true) {
      user.sessionVersion = (user.sessionVersion || 0) + 1;
      await user.save();
    }
  }



  /* ---------------------------------------------
        CUSTOM FIELD EXTRACTION
  --------------------------------------------- */
  extractCustomFields(data) {
    const reserved = ['email', 'password', 'role'];
    const fields = {};

    for (const key of Object.keys(data)) {
      if (!reserved.includes(key)) {
        fields[key] = data[key];
      }
    }

    return fields;
  }
}

module.exports = AuthService;
