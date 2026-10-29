// packages/auth/src/services/session.service.js
/**
 * SessionService — manages user sessions with a global "session version"
 * stamp so that a password change, admin action, or logout-all can invalidate
 * every existing JWT issued before the event.
 *
 * This is the backbone of true "log out everywhere" behaviour.
 */
const ApiError = require('../utils/api-error');

class SessionService {
  constructor(config = {}) {
    this.config = config;
    this.maxSessions = (config.session && config.session.maxSessions) || 5;
    this.sessionExpiryMs =
      (config.session && config.session.sessionExpiryMs) || 30 * 24 * 60 * 60 * 1000; // 30d
    this.ipBinding = (config.session && config.session.ipBinding) || false;
  }

  /**
   * Bump the user's session version. Every existing JWT issued before this
   * moment becomes invalid.
   */
  async bumpSessionVersion(user) {
    user.sessionVersion = (user.sessionVersion || 0) + 1;
    await user.save();
    return user.sessionVersion;
  }

  /**
   * Enforce per-user session cap. If the user has more active sessions than
   * `maxSessions`, drop the oldest ones.
   */
  async enforceSessionCap(user) {
    const sessions = user.sessions || [];
    if (sessions.length <= this.maxSessions) return;

    // sort oldest-first by createdAt
    sessions.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    const toRemove = sessions.length - this.maxSessions;
    sessions.splice(0, toRemove);
    user.sessions = sessions;
    await user.save();
  }

  /**
   * Validate that a decoded JWT's sessionVersion matches the user's current
   * version. If not, the session has been revoked globally.
   */
  validateSession(decoded, user, currentIp = null) {
    const tokenVersion = decoded.sessionVersion || 0;
    const currentVersion = user.sessionVersion || 0;
    if (tokenVersion !== currentVersion) {
      throw ApiError.unauthorized(
        'Session has been invalidated. Please log in again.'
      );
    }

    if (this.ipBinding && currentIp && decoded.ip && decoded.ip !== currentIp) {
      throw ApiError.unauthorized(
        'Session IP address mismatch. Please log in again.'
      );
    }

    return true;
  }

  /**
   * Create a new session record for a user (used during login / social login).
   *
   * Tracks device info (userAgent, IP) and timestamps. If a session for the
   * same device already exists, updates its activity timestamp instead of
   * creating a duplicate — preventing session bloat from repeated logins.
   */
  async createSession(user, info = {}) {
    const crypto = require('crypto');
    const userAgent = info.userAgent || 'unknown';
    const ip = info.ip || 'unknown';

    user.sessions = user.sessions || [];

    // Reuse an existing session from the same device: refresh activity stamp.
    const existing = user.sessions.find(
      (s) => s.userAgent === userAgent && s.ip === ip
    );
    if (existing) {
      existing.lastActiveAt = new Date();
      await this.enforceSessionCap(user);
      return existing;
    }

    const session = {
      sessionId: crypto.randomBytes(16).toString('hex'),
      userAgent,
      ip,
      createdAt: new Date(),
      lastActiveAt: new Date()
    };
    user.sessions.push(session);
    await this.enforceSessionCap(user);
    return session;
  }

  /**
   * Touch a session's activity timestamp (e.g. on token refresh).
   * No-op if the session is not found.
   */
  async touchSession(user, sessionId) {
    if (!user.sessions) return null;
    const session = user.sessions.find((s) => s.sessionId === sessionId);
    if (session) {
      session.lastActiveAt = new Date();
      await user.save();
    }
    return session;
  }

  /**
   * Revoke a single session by sessionId.
   */
  async revokeSession(user, sessionId) {
    if (!user.sessions) return;
    user.sessions = user.sessions.filter((s) => s.sessionId !== sessionId);
    await user.save();
  }

  /**
   * Revoke ALL sessions for a user (logout everywhere).
   */
  async revokeAllSessions(user) {
    user.sessions = [];
    await this.save(user);
    return this.bumpSessionVersion(user);
  }

  async save(user) {
    await user.save();
  }
}

module.exports = SessionService;