// packages/auth/src/utils/password-policy.js
const zxcvbn = require('zxcvbn');
const { getPasswordStrength } = require('./password-strength');

class PasswordPolicy {
  constructor(config = {}) {
    this.config = {
      minLength: config.minLength || 8,
      requireUppercase: config.requireUppercase !== false,
      requireLowercase: config.requireLowercase !== false,
      requireNumbers: config.requireNumbers !== false,
      requireSpecialChars: config.requireSpecialChars !== false,
      passwordHistory: config.passwordHistory || 5,
      expiryDays: config.expiryDays || 90,
      minStrength: config.minStrength || 3
    };
  }

  validate(password, userInfo = {}) {
    const errors = [];

    if (password.length < this.config.minLength)
      errors.push(`Password must be at least ${this.config.minLength} characters long`);

    if (this.config.requireUppercase && !/[A-Z]/.test(password))
      errors.push('Password must contain at least one uppercase letter');

    if (this.config.requireLowercase && !/[a-z]/.test(password))
      errors.push('Password must contain at least one lowercase letter');

    if (this.config.requireNumbers && !/\d/.test(password))
      errors.push('Password must contain at least one number');

    if (this.config.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password))
      errors.push('Password must contain at least one special character');

    const strength = zxcvbn(password, [userInfo.email, userInfo.name]);
    if (strength.score < this.config.minStrength)
      errors.push('Password is too weak. Please choose a stronger password');

    // Lightweight heuristic strength score (0-4), complementing zxcvbn
    const heuristicScore = getPasswordStrength(password);

    return {
      isValid: errors.length === 0,
      errors,
      strength: strength.score,
      strengthScore: heuristicScore
    };
  }

  // History check moved to Model & AuthService
  allowsReuse(password, passwordHistory, bcrypt) {
    return Promise.all(
      passwordHistory.map(old => bcrypt.compare(password, old.hash))
    ).then(matches => !matches.includes(true));
  }

  isExpired(lastChange) {
    if (!this.config.expiryDays) return false;

    const expiryDate =
      new Date(lastChange.getTime() + this.config.expiryDays * 24 * 60 * 60 * 1000);

    return expiryDate < new Date();
  }
}

module.exports = PasswordPolicy;
