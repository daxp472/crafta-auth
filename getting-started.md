# Getting Started with @dax-crafta/auth

Use this guide to wire the library quickly, toggle features on/off, and know what to configure.

## Install
```bash
npm install @dax-crafta/auth
```

Peer: `crafta` must be present in your app.

## Minimal setup
```js
const express = require('express');
const { auth } = require('@dax-crafta/auth');

const app = express();
app.use(express.json());

auth({
  // Optional in local dev; defaults to a safe dev secret with warning
  // env: { JWT_SECRET: process.env.JWT_SECRET },
  mongoUrl: process.env.MONGO_URL,
  // SMTP is optional for local/basic setup.
  // If missing, emailVerification/loginAlerts are auto-disabled.
  // smtp: {
  //   host: process.env.SMTP_HOST,
  //   port: Number(process.env.SMTP_PORT || 587),
  //   auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  //   from: process.env.SMTP_FROM
  // },
  // baseUrl: process.env.BASE_URL,
})(app);

app.listen(3000);
```

### Required
- MongoDB connection (`mongoUrl`) reachable

### Optional (recommended)
- `env.JWT_SECRET` (string). If omitted, the package uses a development default and logs a warning.
- `smtp` + `baseUrl` for email flows. If SMTP is missing, email-related features auto-disable.

### Optional but common
- `enableCSRF: true` to add CSRF protection and `/csrf-token`
- `loginAlerts: true|false` (default true)
- `accessTokenExpiry` (default `1h`), `refreshTokenDays` (default `7`)
- Rate limits: `limits.loginMax`, `limits.twoFAMax`, `limits.forgotPasswordMax`, `limits.refreshMax`

### Feature toggles (simple JSON)
Use `features` to enable/disable behavior without touching code:

```js
auth({
  features: {
    emailVerification: false,
    loginAlerts: false,
    securityAttempts: false,
    rateLimit: true,
    auditLogs: true,
    twoFactor: true,
    csrf: false
  }
})(app);
```

`securityAttempts: false` disables lockout attempt handling and lockout email flow.

## Routes (default paths, all overrideable via `config.routes`)
- `POST /register`
- `POST /login`
- `GET  /verify` (email verification, expects `?token=...`)
- `POST /forgot-password`
- `POST /reset-password`
- `POST /refresh-token`
- `PUT  /profile` (JWT, owner or admin)
- `POST /2fa`
- `POST /roles` (JWT + admin)
- `GET /auth/google` + callback (only if `social.google` configured)

## Feature toggles and how to use

### Email verification
- On by default. Requires `smtp` + `baseUrl`.
- User gets a verification token at register; redeem via `GET /verify?token=...`.
- If you want to disable: `emailVerification: false` (no SMTP required then).

### Password policy
- Configurable via `passwordPolicy`:
  - `minLength`, `requireUppercase`, `requireLowercase`, `requireNumbers`, `requireSpecialChars`, `minStrength` (zxcvbn score), `expiryDays`.
- Enforced on register and reset. Password history (last 5) blocks reuse on reset.

### Security / rate limits / lockout
- Route-level rate limits with `limits.*`.
- Account lockout after `maxLoginAttempts` (default 5) for 1 hour; sends lock email.
- Helmet always on; CSRF optional via `enableCSRF`.

### MFA (TOTP + backup codes)
- Enable per-user: set `twoFactorEnabled: true` and `twoFactorSecret` on the user, or use a provisioning helper (see `src/utils/mfa.js`).
- Login: if 2FA enabled, login returns `{ requires2FA: true, userId }`, then call `POST /2fa` with the code.
- Backup codes: use `authService.generateBackupCodes(userId, app.mfaService)` to issue; users can redeem a code if TOTP fails.

### RBAC
- Role model supports `permissions: [{ resource, actions: ['create'|'read'|'update'|'delete'|'manage'] }]`.
- Middleware: `checkRole(['admin'])`; ownership guard `checkOwnershipOrAdmin`.
- Endpoint: `POST /roles` (admin) to create/update via service.

### Audit logging
- All major flows log to Mongo (AuditLog model) and to `audit.log` (winston).
- Ensure your Mongo URL is set; file log writes to cwd.

### Social login (Google)
- Provide `social.google = { clientID, clientSecret, callbackURL }`.
- Enables `/auth/google` + callback to issue tokens.
- Other providers are placeholders; add strategies if needed.

## Customizing routes
Example:
```js
auth({
  routes: {
    register: '/api/auth/register',
    login: '/api/auth/login',
    verify: '/api/auth/verify-email',
    profile: '/api/me'
  }
})(app);
```

## Error handling
- Errors return JSON `{ success: false, error }` with proper status codes.
- Common statuses: 400 (validation), 401 (auth), 403 (lockout/role), 500 (server).

## Quick checklist before go-live
- Set `JWT_SECRET`, `mongoUrl`, `smtp` (if email verification on).
- Configure `baseUrl` so email links point to your frontend.
- Decide on rate limits and `maxLoginAttempts`.
- Provide `emailTemplateDir` if you want branded emails; otherwise defaults are used.
- Test: register → verify email → login → 2FA (if enabled) → refresh → reset password → profile update → role checks.
