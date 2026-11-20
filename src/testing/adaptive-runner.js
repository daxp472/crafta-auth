const { createLogger } = require('../utils/logger');

// Feature-aware test catalog (mocked; replace run methods with real tests)
const testCatalog = [
  {
    name: 'JWT signing',
    feature: 'jwt',
    run: async (cfg, log) => {
      if (!cfg?.env?.JWT_SECRET) throw new Error('JWT_SECRET missing');
      log.logInfo('JWT secret present; token signing would proceed');
    }
  },
  {
    name: 'Email verification/OTP delivery',
    feature: 'email',
    run: async (cfg, log) => {
      if (!cfg?.smtp) throw new Error('SMTP config missing');
      log.logInfo(`SMTP host: ${cfg.smtp.host}`);
    }
  },
  {
    name: 'OAuth (Google)',
    feature: 'oauth',
    run: async (cfg, log) => {
      if (!cfg?.social?.google) throw new Error('Google config missing');
      log.logInfo('Google OAuth config present; would start redirect flow');
    }
  },
  {
    name: '2FA (TOTP)',
    feature: 'twofa',
    run: async (_cfg, log) => {
      log.logInfo('2FA code verification simulated');
    }
  }
];

function inferFeatureFlags(authConfig = {}) {
  return {
    jwt: true, // core always on
    email: !!(authConfig.emailVerification && authConfig.smtp),
    oauth: !!(authConfig.social && authConfig.social.google),
    twofa: true, // library supports 2FA routes by default
    socialAccountLinking: authConfig.features?.socialAccountLinking === true,
    sessionManagement: authConfig.features?.sessionManagement === true,
    passwordStrengthMeter: authConfig.features?.passwordStrengthMeter === true,
    passwordless: authConfig.features?.passwordless === true,
    emailOtp: authConfig.features?.emailOtp === true,
    adminPanel: authConfig.features?.adminPanel === true,
    webhooks: !!authConfig.webhooks?.url,
    auditLogs: authConfig.features?.auditLogs !== false
  };
}

async function runAdaptiveTests(authConfig = {}, featureFlags, opts = {}) {
  const flags = featureFlags || inferFeatureFlags(authConfig);
  const log = createLogger(opts.logging !== false);

  log.logInfo('Adaptive test runner starting…');

  for (const test of testCatalog) {
    if (!flags[test.feature]) {
      log.logSkip(`${test.name} - feature disabled`);
      continue;
    }
    try {
      await test.run(authConfig, log);
      log.logSuccess(test.name);
    } catch (err) {
      log.logError(`${test.name} failed: ${err.message}`);
    }
  }

  log.logSuccess('Adaptive tests complete.');
  return true;
}

module.exports = {
  runAdaptiveTests,
  inferFeatureFlags,
  testCatalog
};
