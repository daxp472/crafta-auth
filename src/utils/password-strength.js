// packages/auth/src/utils/password-strength.js
/**
 * Password strength scoring utility.
 *
 * Returns a strength score from 0 (very weak) to 4 (very strong) based on
 * length, character variety, and common-pattern detection.
 *
 * This complements the zxcvbn-based strength check inside PasswordPolicy,
 * providing a lightweight, dependency-free heuristic for quick feedback.
 */
const COMMON_PASSWORDS = [
  'password', '123456', '12345678', '123456789', 'qwerty', 'abc123',
  '111111', '123123', 'admin', 'letmein', 'welcome', 'monkey',
  'football', 'iloveyou', 'sunshine', 'princess', 'dragon', 'baseball'
];

const COMMON_SEQUENCES = [
  'abcdefghijklmnopqrstuvwxyz',
  '0123456789',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm'
];

function hasCommonSequence(password, length) {
  const lower = password.toLowerCase();
  for (const seq of COMMON_SEQUENCES) {
    for (let i = 0; i + length <= seq.length; i++) {
      if (lower.includes(seq.slice(i, i + length))) return true;
    }
  }
  return false;
}

/**
 * Calculate a strength score (0-4) for a password.
 *
 * @param {string} password - The password to evaluate.
 * @returns {number} Score from 0 (very weak) to 4 (very strong).
 */
function getPasswordStrength(password) {
  if (!password || typeof password !== 'string') return 0;

  const lower = password.toLowerCase();
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);

  let score = 0;

  // Length scoring
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;

  // Complexity scoring
  const varietyCount = [hasLower, hasUpper, hasNumber, hasSpecial].filter(Boolean).length;
  if (varietyCount >= 3) score++;

  // Penalize common patterns
  if (COMMON_PASSWORDS.includes(lower)) return 0;
  if (hasCommonSequence(password, 3)) score--;
  if (/(.)\1{2,}/.test(password)) score--; // repeated chars like "aaa"

  return Math.max(0, Math.min(4, score));
}

module.exports = { getPasswordStrength };
