const passport = require('passport');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const helmet = require("helmet");
const mongoose = require("mongoose");
const jwt = require('jsonwebtoken');

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const AuthService = require('./services/auth.service');
const RoleService = require('./services/role.service');
const AuditService = require('./services/audit.service');
const SessionService = require('./services/session.service');
const WebhookService = require('./services/webhook.service');
const PasswordlessService = require('./services/passwordless.service');
const MFAService = require('./utils/mfa');
const PasswordPolicy = require('./utils/password-policy');
const createAuthMiddleware = require('./middlewares/auth.middleware');
const corsMiddleware = require('./middlewares/cors.middleware');
const validators = require('./middlewares/validation.middleware');
const { createLogger } = require('./utils/logger');
const ApiError = require('./utils/api-error');
const { getPasswordStrength } = require('./utils/password-strength');
const { runAdaptiveTests, inferFeatureFlags, testCatalog } = require('./testing/adaptive-runner');


const defaultConfig = {
  strategy: 'jwt',
  fields: ['email', 'password'],
  routes: {
    register: '/register',
    login: '/login',
    verify: '/verify',
    forgotPassword: '/forgot-password',
    resetPassword: '/reset-password',
    refreshToken: '/refresh-token',
    profile: '/profile',
    twoFactor: '/2fa',
    roles: '/roles',
    permissions: '/permissions',
    magicLink: '/auth/magic-link',
    magicLinkVerify: '/auth/magic-link/verify'
  },
  mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/forge-auth',
  maxLoginAttempts: 5,
  emailVerification: true,
  loginAlerts: true,
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    expiryDays: 90
  },
  smtp: null,
  social: {
    google: null,
    facebook: null,
    github: null
  },
  features: {
    emailVerification: true,
    loginAlerts: true,
    securityAttempts: true,
    rateLimit: true,
    auditLogs: true,
    twoFactor: true,
    csrf: false,
    passwordless: false,
    webhooks: false
  },
  env: {
    JWT_SECRET: process.env.JWT_SECRET || 'crafta-auth-dev-secret'
  },
  accessTokenExpiry: '1h',
  refreshTokenDays: 7,
  cors: {
    origin: '*',
    credentials: true
  },
  webhooks: null,
  session: {
    maxSessions: 5,
    sessionExpiryMs: 30 * 24 * 60 * 60 * 1000,
    warningThresholdMs: 5 * 60 * 1000
  }
};

function auth(config = {}) {
  const finalConfig = {
    ...defaultConfig,
    ...config,
    routes: { ...defaultConfig.routes, ...(config.routes || {}) },
    passwordPolicy: { ...defaultConfig.passwordPolicy, ...(config.passwordPolicy || {}) },
    social: { ...defaultConfig.social, ...(config.social || {}) },
    limits: { ...(config.limits || {}) },
    features: { ...defaultConfig.features, ...(config.features || {}) },
    cors: { ...defaultConfig.cors, ...(config.cors || {}) },
    session: { ...defaultConfig.session, ...(config.session || {}) }
  };

  finalConfig.env = { ...(defaultConfig.env || {}), ...(config.env || process.env) };
  const logger = createLogger(finalConfig.logging !== false);

  const featureBools = {
    emailVerification: config.emailVerification,
    loginAlerts: config.loginAlerts,
    csrf: config.enableCSRF
  };

  Object.keys(featureBools).forEach((key) => {
    if (typeof featureBools[key] === 'boolean') {
      finalConfig.features[key] = featureBools[key];
    }
  });

  finalConfig.emailVerification = finalConfig.features.emailVerification;
  finalConfig.loginAlerts = finalConfig.features.loginAlerts;
  finalConfig.enableCSRF = finalConfig.features.csrf;

  if (finalConfig.features.securityAttempts === false) {
    finalConfig.loginAlerts = false;
    finalConfig.features.loginAlerts = false;
  }

  if (finalConfig.env?.JWT_SECRET === 'crafta-auth-dev-secret') {
    logger.logWarn('JWT_SECRET not provided; using development default secret. Set env.JWT_SECRET in production.');
  }

  const smtpEnabled = !!(
    finalConfig.smtp &&
    finalConfig.smtp.host &&
    finalConfig.smtp.port &&
    finalConfig.smtp.auth &&
    finalConfig.smtp.auth.user &&
    finalConfig.smtp.auth.pass &&
    finalConfig.smtp.from
  );

  if (!smtpEnabled && finalConfig.features.emailVerification) {
    logger.logWarn('SMTP not configured; emailVerification auto-disabled.');
    finalConfig.features.emailVerification = false;
    finalConfig.emailVerification = false;
  }

  if (!smtpEnabled && finalConfig.features.loginAlerts) {
    logger.logWarn('SMTP not configured; loginAlerts auto-disabled.');
    finalConfig.features.loginAlerts = false;
    finalConfig.loginAlerts = false;
  }

  // Passwordless requires SMTP for magic link delivery
  if (finalConfig.features.passwordless && !smtpEnabled) {
    logger.logWarn('SMTP not configured; passwordless (magic links) auto-disabled.');
    finalConfig.features.passwordless = false;
  }

  // ------------------------------------------
  // MongoDB Connection — support external connections
  // ------------------------------------------
  const connectDB = () => {
    mongoose.connect(finalConfig.mongoUrl)
      .then(() => logger.logSuccess("MongoDB connected"))
      .catch(err => {
        logger.logError(`MongoDB connection error: ${err.message}`);
        setTimeout(connectDB, 5000);
      });
  };

  if (finalConfig.mongooseConnection) {
    // Allow host app to pass an existing mongoose connection
    logger.logInfo("Using provided mongoose connection");
  } else if (mongoose.connection.readyState === 0) {
    connectDB();
    mongoose.connection.on('disconnected', () => {
      logger.logWarn("MongoDB disconnected, attempting to reconnect...");
      connectDB();
    });
  } else {
    logger.logInfo("Using existing mongoose connection");
  }
  // ------------------------------------------

  const auditService = finalConfig.features.auditLogs ? new AuditService() : null;
  const mfaService = new MFAService();
  const sessionService = new SessionService(finalConfig);
  const webhookService = new WebhookService(finalConfig);

  // Pass shared services into AuthService config so it can log/audit correctly
  const authService = new AuthService({
    ...finalConfig,
    auditService,
    mfaService,
    sessionService,
    webhookService
  });
  const roleService = new RoleService();
  const passwordPolicy = new PasswordPolicy(finalConfig.passwordPolicy);
  const passwordlessService = finalConfig.features.passwordless
    ? new PasswordlessService({ ...finalConfig, emailService: authService.emailService })
    : null;

  const { rateLimiter, limiterFor, verifyToken, checkRole, checkOwnershipOrAdmin } = createAuthMiddleware(finalConfig);

  if (finalConfig.social && finalConfig.social.google) {
    passport.use(new GoogleStrategy(finalConfig.social.google,
      async (accessToken, refreshToken, profile, done) => {
        try {
          const user = await authService.handleSocialLogin('google', profile);
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    ));
  }

  return function (app) {
    const safeAudit = async (entry) => {
      if (!auditService) return;
      try {
        await auditService.logActivity(entry);
      } catch (err) {
        logger.logWarn(`Audit logging failed: ${err.message}`);
      }
    };

    const safeWebhook = async (event, data) => {
      if (!finalConfig.features.webhooks) return;
      try {
        await webhookService.emit(event, data);
      } catch (err) {
        logger.logWarn(`Webhook delivery failed: ${err.message}`);
      }
    };

    // ------------------------------------------
    // SESSION TIMEOUT WARNING MIDDLEWARE
    // ------------------------------------------
    const warningThresholdMs = finalConfig.session?.warningThresholdMs || 5 * 60 * 1000;
    app.use((req, res, next) => {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
          const decoded = jwt.decode(token);
          if (decoded && decoded.exp) {
            const timeLeft = decoded.exp * 1000 - Date.now();
            if (timeLeft > 0 && timeLeft < warningThresholdMs) {
              res.setHeader('X-Session-Expires-In', Math.floor(timeLeft / 1000));
            }
          }
        } catch (err) {
          // Ignore decoding errors in middleware
        }
      }
      next();
    });

    app.use(cookieParser());

    // CORS — applied before routes
    app.use(corsMiddleware(finalConfig));

    if (finalConfig.enableCSRF) {
      const csrfProtection = csrf({ cookie: true });
      app.use(csrfProtection);

      app.get('/csrf-token', (req, res) => {
        res.json({ csrfToken: req.csrfToken() });
      });
    }

    app.use(passport.initialize());
    app.use(rateLimiter);
    app.use(helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    }));

    app.authService = authService;
    app.roleService = roleService;
    app.auditService = auditService;
    app.mfaService = mfaService;
    app.sessionService = sessionService;
    app.webhookService = webhookService;
    app.passwordlessService = passwordlessService;
    app.passwordPolicy = passwordPolicy;
    app.authLogger = logger;

    // ------------------------------------------
    // HEALTH CHECK
    // ------------------------------------------
    app.get('/auth/health', async (req, res) => {
      const dbState = mongoose.connection.readyState;
      const dbStatus = dbState === 1 ? 'connected' : dbState === 2 ? 'connecting' : 'disconnected';

      // Get active session count
      let activeSessions = 0;
      if (mongoose.connection.readyState === 1) {
        try {
          activeSessions = await mongoose.connection.db.collection('users').aggregate([
            { $match: { sessions: { $exists: true, $not: { $size: 0 } } } },
            { $unwind: '$sessions' },
            { $match: { 'sessions.createdAt': { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } } },
            { $group: { _id: '$_id', count: { $sum: 1 } } },
            { $group: { _id: null, total: { $sum: '$count' } } }
          ]).toArray();
          activeSessions = activeSessions[0]?.total || 0;
        } catch (err) {
          logger.logWarn(`Failed to count active sessions: ${err.message}`);
        }
      }

      // Get memory usage
      const memoryUsage = process.memoryUsage();

      // Get uptime
      const uptime = process.uptime();

      res.json({
        success: true,
        status: 'ok',
        db: dbStatus,
        version: require('../package.json').version,
        uptime: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`,
        activeSessions,
        memoryUsage: {
          rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
          heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
          heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`
        },
        features: {
          emailVerification: finalConfig.features.emailVerification,
          twoFactor: finalConfig.features.twoFactor,
          passwordless: finalConfig.features.passwordless,
          auditLogs: finalConfig.features.auditLogs,
          webhooks: finalConfig.features.webhooks,
          csrf: finalConfig.features.csrf,
          rateLimit: finalConfig.features.rateLimit
        }
      });
    });

    // EMAIL VERIFICATION
    app.get(
      finalConfig.routes.verify,
      async (req, res, next) => {
        try {
          const token = req.query.token;
          const user = await authService.verifyEmail(token);

          res.json({
            success: true,
            message: 'Email verified successfully',
            userId: user._id
          });
        } catch (err) {
          next(err);
        }
      }
    );

    // REGISTER
    app.post(
      finalConfig.routes.register,
      limiterFor('register'),
      validators.registerValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const { isValid, errors } = passwordPolicy.validate(req.body.password, {
            email: req.body.email,
            name: req.body.name
          });

          if (!isValid) {
            throw ApiError.passwordPolicy('Password policy violation', errors);
          }

          const user = await authService.register(req.body);
          await safeAudit({
            userId: user._id,
            action: 'register',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
          });
          await safeWebhook('user.registered', { userId: user._id, email: user.email });

          logger.logSuccess('User registered');
          res.status(201).json({ success: true, message: 'Registration successful' });
        } catch (err) {
          logger.logError(`Register failed: ${err.message}`);
          next(err);
        }
      }
    );

    // LOGIN
    app.post(
      finalConfig.routes.login,
      limiterFor('login'),
      validators.loginValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const deviceInfo = { userAgent: req.headers['user-agent'], ip: req.ip };
          const result = await authService.login(req.body.email, req.body.password, deviceInfo);

          await safeAudit({
            userId: result.user?._id,
            action: 'login',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
          });
          await safeWebhook('user.login', { userId: result.user?._id });

          logger.logSuccess('Login successful');
          res.json({ success: true, ...result });
        } catch (err) {
          await safeAudit({
            action: 'login',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'failure',
            details: { error: err.message }
          });
          logger.logError(`Login failed: ${err.message}`);
          next(err);
        }
      }
    );

    // 2FA
    if (finalConfig.features.twoFactor !== false) {
      app.post(
        finalConfig.routes.twoFactor,
        limiterFor('2fa'),
        validators.twoFAValidator,
        validators.handleValidation,
        async (req, res, next) => {
          try {
            const result = await authService.verify2FA(req.body.userId, req.body.code);
            await safeAudit({ userId: result.user._id, action: '2fa_verify', status: 'success' });
            logger.logSuccess('2FA verified');
            res.json({ success: true, ...result });
          } catch (err) {
            logger.logError(`2FA failed: ${err.message}`);
            next(err);
          }
        }
      );
    }

    // PASSWORDLESS / MAGIC LINK
    if (finalConfig.features.passwordless && passwordlessService) {
      app.post(
        finalConfig.routes.magicLink,
        limiterFor('login'),
        async (req, res, next) => {
          try {
            const email = req.body.email;
            if (!email) throw ApiError.validation('Email is required');
            const baseUrl = finalConfig.baseUrl || `${req.protocol}://${req.get('host')}`;
            await passwordlessService.requestMagicLink(email, baseUrl);
            res.json({ success: true, message: 'Magic link sent if email exists' });
          } catch (err) {
            next(err);
          }
        }
      );

      app.get(
        finalConfig.routes.magicLinkVerify,
        async (req, res, next) => {
          try {
            const token = req.query.token;
            if (!token) throw ApiError.invalidToken('Magic link token is required');
            const user = await passwordlessService.verifyMagicLink(token);
            const tokens = await authService.generateTokens(user);
            await safeAudit({ userId: user._id, action: 'login', status: 'success', details: { method: 'magic_link' } });
            await safeWebhook('user.login', { userId: user._id, method: 'magic_link' });
            res.json({ success: true, ...tokens, user });
          } catch (err) {
            next(err);
          }
        }
      );
    }

    // FORGOT PASSWORD
    app.post(
      finalConfig.routes.forgotPassword,
      limiterFor('forgotPassword'),
      validators.forgotPasswordValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          await authService.forgotPassword(req.body.email);
          logger.logInfo('Password reset email triggered');
          res.json({ success: true, message: 'Password reset email sent if user exists' });
        } catch (err) {
          logger.logError(`Forgot password failed: ${err.message}`);
          next(err);
        }
      }
    );

    // RESET PASSWORD
    app.post(
      finalConfig.routes.resetPassword,
      validators.resetPasswordValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          await authService.resetPassword(req.body.token, req.body.newPassword);
          await safeAudit({ action: 'password_reset', status: 'success' });
          await safeWebhook('user.password_changed', { token: req.body.token });
          logger.logSuccess('Password reset completed');
          res.json({ success: true, message: 'Password reset successful' });
        } catch (err) {
          logger.logError(`Reset password failed: ${err.message}`);
          next(err);
        }
      }
    );

    // REFRESH TOKEN
    app.post(
      finalConfig.routes.refreshToken,
      limiterFor('refreshToken'),
      validators.refreshTokenValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const result = await authService.refreshToken(req.body.refreshToken);
          logger.logSuccess('Token refreshed');
          res.json({ success: true, ...result });
        } catch (err) {
          logger.logError(`Refresh token failed: ${err.message}`);
          next(err);
        }
      }
    );

    // LOGOUT
    app.post(
      '/logout',
      verifyToken,
      async (req, res, next) => {
        try {
          await authService.logout(req.user.id, req.body.sessionId);
          await safeAudit({ userId: req.user.id, action: 'logout', status: 'success' });
          await safeWebhook('user.logout', { userId: req.user.id });
          res.json({ success: true, message: 'Logged out successfully' });
        } catch (err) {
          next(err);
        }
      }
    );

    // LOGOUT ALL DEVICES
    app.post(
      '/logout-all',
      verifyToken,
      async (req, res, next) => {
        try {
          const User = require('./models/user');
          const user = await User.findById(req.user.id);
          if (!user) throw ApiError.notFound('User not found');
          await sessionService.revokeAllSessions(user);
          await user.revokeAllRefreshTokens();
          await safeAudit({ userId: req.user.id, action: 'logout', status: 'success', details: { all: true } });
          res.json({ success: true, message: 'All sessions revoked' });
        } catch (err) {
          next(err);
        }
      }
    );

    // UPDATE PROFILE
    app.put(
      finalConfig.routes.profile,
      verifyToken,
      checkOwnershipOrAdmin((req) => req.user.id),
      validators.profileUpdateValidator,
      validators.handleValidation,
      async (req, res, next) => {
        try {
          const user = await authService.updateProfile(req.user.id, req.body);
          await safeAudit({ userId: user._id, action: 'profile_update', status: 'success' });
          logger.logSuccess('Profile updated');
          res.json({ success: true, user });
        } catch (err) {
          logger.logError(`Profile update failed: ${err.message}`);
          next(err);
        }
      }
    );

    // CREATE ROLE (ADMIN)
    app.post('/roles', verifyToken, checkRole(['admin']), async (req, res, next) => {
      try {
        const role = await roleService.createRole(req.body);
        res.status(201).json({ success: true, role });
      } catch (err) {
        next(err);
      }
    });

    // GOOGLE OAUTH
    if (finalConfig.social && finalConfig.social.google) {
      app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

      app.get('/auth/google/callback',
        passport.authenticate('google', { session: false }),
        async (req, res, next) => {
          try {
            const tokens = await authService.generateTokens(req.user);
            await safeAudit({
              userId: req.user._id,
              action: 'social_login',
              status: 'success',
              details: { provider: 'google' }
            });
            await safeWebhook('user.login', { userId: req.user._id, method: 'social', provider: 'google' });
            logger.logSuccess('Google OAuth success');
            res.json({ success: true, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user: req.user });
          } catch (err) {
            logger.logError(`Google OAuth failed: ${err.message}`);
            next(err);
          }
        });
    }

    // ------------------------------------------
    // STANDARDIZED ERROR HANDLER
    // ------------------------------------------
    app.use((err, req, res, next) => {
      // Normalize any error into our ApiError shape
      const apiErr = ApiError.normalize(err);

      // Log stack only in development
      if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === undefined) {
        logger.logError(`[${apiErr.code}] ${apiErr.message}`);
      } else {
        // In production, only log server errors with stack
        if (apiErr.status >= 500) {
          logger.logError(`[${apiErr.code}] ${apiErr.message}`);
        }
      }

      const response = {
        success: false,
        code: apiErr.code,
        error: apiErr.message
      };

      if (apiErr.details) {
        response.details = apiErr.details;
      }

      res.status(apiErr.status).json(response);
    });
  };
}

module.exports = { auth, ApiError, getPasswordStrength, runAdaptiveTests, inferFeatureFlags, testCatalog };
