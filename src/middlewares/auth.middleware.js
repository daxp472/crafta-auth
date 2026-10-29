// packages/auth/src/middlewares/auth.middleware.js
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const ApiError = require('../utils/api-error');

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

  // Register limiter
  const registerLimiter = rateLimitEnabled ? rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config?.limits?.registerMax || 20,
    message: { success: false, error: 'Too many registration attempts, please try later' },
    standardHeaders: true,
    legacyHeaders: false
  }) : noOpLimiter;

  // Expose function to choose limiter per-route
  const limiterFor = (routeName) => {
    const routeLimits = {
      login: loginLimiter,
      '2fa': twoFALimiter,
      forgotPassword: forgotPasswordLimiter,
      refreshToken: refreshLimiter,
      refresh: refreshLimiter,
      register: registerLimiter
    };

    if (config.limits && config.limits[routeName]) {
      return rateLimit({
        windowMs: 15 * 60 * 1000,
        max: config.limits[routeName],
        standardHeaders: true,
        legacyHeaders: false
      });
    }

    return routeLimits[routeName] || genericLimiter;
  };


  const extractToken = (req) => {
    const headers = req.headers || {};
    let authHeader = headers.authorization;
    // Guard: duplicate headers arrive as arrays — take first string element
    if (Array.isArray(authHeader)) {
      authHeader = authHeader.find(h => typeof h === 'string') || null;
    }
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      return authHeader.split(' ')[1];
    }

    let xAccess = headers['x-access-token'];
    if (Array.isArray(xAccess)) {
      xAccess = xAccess.find(h => typeof h === 'string') || null;
    }
    if (typeof xAccess === 'string') {
      return xAccess;
    }

    return null;
  };

  const verifyToken = async (req, res, next) => {
    const token = extractToken(req);
    if (!token) {
      return next(ApiError.unauthorized('No token provided'));
    }

    try {
      const decoded = jwt.verify(token, config.env.JWT_SECRET);

      // Validate session version and IP binding if sessionService is available
      if (req.app && req.app.sessionService) {
        const User = require('../models/user');
        const user = await User.findById(decoded.id);
        if (!user) {
          return next(ApiError.unauthorized('User not found'));
        }
        req.app.sessionService.validateSession(decoded, user, req.ip);
      }

      // keep minimal user data on req.user
      req.user = { id: decoded.id, role: decoded.role, email: decoded.email };
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return next(ApiError.expiredToken());
      }
      return next(ApiError.invalidToken());
    }
  };

  const checkRole = (roles = []) => {
    return (req, res, next) => {
      if (!req.user) {
        return next(ApiError.unauthorized());
      }
      if (!roles.includes(req.user.role)) {
        return next(ApiError.forbidden());
      }
      next();
    };
  };

  // Ownership check middleware for IDOR protection: allow if owner or admin
  const checkOwnershipOrAdmin = (getTargetUserId) => {
    return async (req, res, next) => {
      try {
        const targetId = typeof getTargetUserId === 'function' ? getTargetUserId(req) : req.params.id;
        if (!req.user) return next(ApiError.unauthorized());
        if (req.user.role === 'admin' || String(req.user.id) === String(targetId)) {
          return next();
        }
        return next(ApiError.forbidden('Insufficient permissions to modify this resource'));
      } catch (err) {
        return next(ApiError.internal('Server error'));
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
