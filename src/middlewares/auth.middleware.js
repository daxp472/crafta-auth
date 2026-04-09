// packages/auth/src/middlewares/auth.middleware.js
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const createAuthMiddleware = (config) => {
  const noOpLimiter = (_req, _res, next) => next();
  const rateLimitEnabled = config?.features?.rateLimit !== false;

  // Default generic limiter (used for non-sensitive endpoints)
  const genericLimiter = rateLimitEnabled ? rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
  }) : noOpLimiter;

  // Sensitive endpoint limiters - tuned for production
  const loginLimiter = rateLimitEnabled ? rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config?.limits?.loginMax || 10, // default 10 attempts per 15m
    message: { success: false, error: 'Too many login attempts, please try later' },
    standardHeaders: true,
    legacyHeaders: false
  }) : noOpLimiter;

  const twoFALimiter = rateLimitEnabled ? rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config?.limits?.twoFAMax || 20, // 20 per 15m
    message: { success: false, error: 'Too many 2FA attempts, please try later' },
    standardHeaders: true,
    legacyHeaders: false
  }) : noOpLimiter;

  const forgotPasswordLimiter = rateLimitEnabled ? rateLimit({
    windowMs: 60 * 60 * 1000,
    max: config?.limits?.forgotPasswordMax || 5, // 5 per hour
    message: { success: false, error: 'Too many password reset requests, please try later' },
    standardHeaders: true,
    legacyHeaders: false
  }) : noOpLimiter;

  // Refresh token limiter
  const refreshLimiter = rateLimitEnabled ? rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config?.limits?.refreshMax || 30,
    message: { success: false, error: 'Too many refresh attempts' }
  }) : noOpLimiter;

  // Expose function to choose limiter per-route
  const limiterFor = (routeName) => {
    switch (routeName) {
      case 'login': return loginLimiter;
      case '2fa': return twoFALimiter;
      case 'forgotPassword': return forgotPasswordLimiter;
      case 'refreshToken': return refreshLimiter;
      case 'refresh': return refreshLimiter;
      default: return genericLimiter;
    }
  };


  const verifyToken = (req, res, next) => {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }
    const token = header.split(' ')[1];
    try {
      const decoded = jwt.verify(token, config.env.JWT_SECRET);
      // keep minimal user data on req.user
      req.user = { id: decoded.id, role: decoded.role, email: decoded.email };
      next();
    } catch (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
  };

  const checkRole = (roles = []) => {
    return (req, res, next) => {
      if (!req.user) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
      }
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ success: false, error: 'Insufficient permissions' });
      }
      next();
    };
  };

  // Ownership check middleware for IDOR protection: allow if owner or admin
  const checkOwnershipOrAdmin = (getTargetUserId) => {
    return async (req, res, next) => {
      try {
        const targetId = typeof getTargetUserId === 'function' ? getTargetUserId(req) : req.params.id;
        if (!req.user) return res.status(401).json({ success: false, error: 'Unauthorized' });
        if (req.user.role === 'admin' || String(req.user.id) === String(targetId)) {
          return next();
        }
        return res.status(403).json({ success: false, error: 'Insufficient permissions to modify this resource' });
      } catch (err) {
        return res.status(500).json({ success: false, error: 'Server error' });
      }
    };
  };

  return {
    rateLimiter: genericLimiter,
    limiterFor,
    verifyToken,
    checkRole,
    checkOwnershipOrAdmin
  };
};

module.exports = createAuthMiddleware;
