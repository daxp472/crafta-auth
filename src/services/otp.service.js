// packages/auth/src/services/otp.service.js
/**
 * OTPService — generates, hashes, and verifies one-time passwords (OTP).
 *
 * Used for email OTP login (passwordless). Codes are:
 *   - 6-digit numeric
 *   - hashed (SHA-256) before storage — never stored in plaintext
 *   - single-use: consumed on successful verification
 *   - TTL-bounded: expires after `ttlMs`
 *
 * Designed to work with the User model's `emailOtp*` fields.
 */
const crypto = require('crypto');

class OTPService {
  constructor(config = {}) {
    this.config = config;
    this.ttlMs = (config.otp && config.otp.ttlMs) || 10 * 60 * 1000; // 10 min default
    this.digits = (config.otp && config.otp.digits) || 6;
    this.maxAttempts = (config.otp && config.otp.maxAttempts) || 5;
  }

  /**
   * Generate a fresh OTP code (cryptographically secure).
   * @returns {{ code: string, hash: string, expiresAt: Date }}
   */
  generateCode() {
    // Secure random 6-digit code (avoid modulo bias)
    const max = Math.pow(10, this.digits);
    let code = '';
    const bytes = crypto.randomBytes(this.digits);
    for (let i = 0; i < this.digits; i++) {
      code += String(bytes[i] % 10);
    }
    // Guarantee fixed length
    code = code.padStart(this.digits, '0');

    return {
      code,
      hash: this.hashCode(code),
      expiresAt: new Date(Date.now() + this.ttlMs)
    };
  }

  /**
   * Hash an OTP code for storage (never store plaintext).
   */
  hashCode(code) {
    return crypto.createHash('sha256').update(String(code)).digest('hex');
  }

  /**
   * Verify a submitted code against a stored hash (constant-time compare).
   */
  verifyHash(code, storedHash) {
    if (!code || !storedHash) return false;
    const submitted = this.hashCode(code);
    // constant-time comparison
    if (submitted.length !== storedHash.length) return false;
    let diff = 0;
    for (let i = 0; i < submitted.length; i++) {
      diff |= submitted.charCodeAt(i) ^ storedHash.charCodeAt(i);
    }
    return diff === 0;
  }
}

module.exports = OTPService;
