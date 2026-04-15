const passport = require('passport');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const helmet = require("helmet");
const mongoose = require("mongoose");   // <<< FIX ADDED

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const AuthService = require('./services/auth.service');
const RoleService = require('./services/role.service');
const AuditService = require('./services/audit.service');
const MFAService = require('./utils/mfa');
const PasswordPolicy = require('./utils/password-policy');
const createAuthMiddleware = require('./middlewares/auth.middleware');
const validators = require('./middlewares/validation.middleware');
const { createLogger } = require('./utils/logger');
const ApiError = require('./utils/api-error');
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
    permissions: '/permissions'
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
    csrf: false
  },
  env: {
    JWT_SECRET: process.env.JWT_SECRET || 'crafta-auth-dev-secret'
  },
  accessTokenExpiry: '1h',
  refreshTokenDays: 7
};

function auth(config = {}) {
  const finalConfig = {
    ...defaultConfig,
    ...config,
    routes: { ...defaultConfig.routes, ...(config.routes || {}) },
    passwordPolicy: { ...defaultConfig.passwordPolicy, ...(config.passwordPolicy || {}) },
    social: { ...defaultConfig.social, ...(config.social || {}) },
    limits: { ...(config.limits || {}) },
    features: { ...defaultConfig.features, ...(config.features || {}) }
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

  // ------------------------------------------
  // ✅ Proper MongoDB Connection
  // ------------------------------------------
  if (mongoose.connection.readyState === 0) {
    mongoose.connect(finalConfig.mongoUrl, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    })
      .then(() => logger.logSuccess("MongoDB connected"))
      .catch(err => logger.logError(`MongoDB connection error: ${err.message}`));
  } else {
    logger.logInfo("Using existing mongoose connection");
  }
  // ------------------------------------------

  const auditService = finalConfig.features.auditLogs ? new AuditService() : null;
  const mfaService = new MFAService();

  // Pass shared services into AuthService config so it can log/audit correctly
  const authService = new AuthService({
    ...finalConfig,
    auditService,
    mfaService
  });
  const roleService = new RoleService();
  const passwordPolicy = new PasswordPolicy(finalConfig.passwordPolicy);
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

    app.use(cookieParser());

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
    app.passwordPolicy = passwordPolicy;
    app.authLogger = logger;

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
            return res.status(400).json({ success: false, error: 'Password policy violation', details: errors });
          }

          const user = await authService.register(req.body);
          await safeAudit({
            userId: user._id,
            action: 'register',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            status: 'success'
          });

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
            logger.logSuccess('Google OAuth success');
            res.json({ success: true, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken, user: req.user });
          } catch (err) {
            logger.logError(`Google OAuth failed: ${err.message}`);
            next(err);
          }
        });
    }

    // ERROR HANDLER
    app.use((err, req, res, next) => {
      console.error(err && err.stack ? err.stack : err);
      const status = err.status || (err.name === 'ValidationError' ? 400 : 500);

      let message;
      if (status >= 400 && status < 500) {
        message = err.message || 'Bad request';
      } else {
        message = process.env.NODE_ENV === 'development'
          ? (err.message || 'Internal Server Error')
          : 'Internal Server Error';
      }

      logger.logError(`Error ${status}: ${message}`);
      res.status(status).json({ success: false, error: message });
    });
  };
}

module.exports = { auth, ApiError, runAdaptiveTests, inferFeatureFlags, testCatalog };