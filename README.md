# @dax-crafta/auth

Production-ready authentication library for Crafta apps, featuring plug-and-play defaults, robust security, and clean JSON-based customization.

[![npm version](https://img.shields.io/npm/v/@dax-crafta/auth.svg)](https://www.npmjs.com/package/@dax-crafta/auth)
[![npm downloads](https://img.shields.io/npm/dm/@dax-crafta/auth.svg)](https://www.npmjs.com/package/@dax-crafta/auth)
[![License](https://img.shields.io/npm/l/@dax-crafta/auth.svg)](https://github.com/NPM-crafta/crafta-auth/blob/main/LICENSE)

## Features
1. **JWT Authentication**: Secure sessions with automatic refresh token rotation.
2. **Standard Routes**: Built-in register, login, verify email, forgot/reset password, and refresh routes.
3. **Multi-Factor Authentication (MFA)**: Optional TOTP-based 2FA with backup codes support.
4. **RBAC**: Role-Based Access Control service to manage permissions and roles.
5. **Rate Limiting**: Route-level protection for sensitive endpoints (login, register, 2FA).
6. **Password Policy**: Strict policy enforcement with password history checks and strength validation.
7. **Google OAuth**: Optional social login integration.
8. **Audit Logs**: Comprehensive logging to MongoDB and local files.
9. **Session Management**: Full session control with per-user session limits and global logout.
10. **Webhooks**: Real-time event notifications for auth lifecycle events (registered, login, logout, password change).
11. **Passwordless Login**: Magic link authentication.
12. **Standardized Error Handling**: Unified error format with 19 distinct `AUTH_*` codes.
13. **CORS Middleware**: Explicit origin whitelisting for secure cross-origin requests.
14. **Customizable Fields**: Flexible user model customization.

## Install
```bash
npm install @dax-crafta/auth
```

## Minimal Setup
```javascript
const { crafta } = require('crafta');
const { auth } = require('@dax-crafta/auth');

const app = crafta();

auth({
  env: {
    JWT_SECRET: process.env.JWT_SECRET || 'dev-secret-123'
  },
  mongoUrl: process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/crafta-auth-demo'
})(app);

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
```

## Configuration Options
The library is configured via a single object passed to the `auth()` function:

```javascript
auth({
  strategy: 'jwt', // Currently defaults to 'jwt'
  fields: ['name', 'email', 'password'],
  routes: { /* Custom route paths */ },
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    expiryDays: 90
  },
  limits: {
    loginMax: 10,
    registerMax: 20
  }
})(app);
```

## Feature Toggles
Enable or disable features via the `features` object:

```javascript
auth({
  features: {
    emailVerification: true,
    twoFactor: true,
    passwordless: false,
    auditLogs: true,
    webhooks: false,
    rateLimit: true,
    csrf: false
  }
})(app);
```

## Email Setup
Configure SMTP to enable email-based features (Verification, Forgot Password, Magic Links, Login Alerts):

```javascript
auth({
  smtp: {
    host: process.env.SMTP_HOST,
    port: 587,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    from: process.env.SMTP_FROM
  },
  baseUrl: 'http://localhost:3000'
})(app);
```

## Google OAuth Setup
```javascript
auth({
  social: {
    google: {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/callback'
    }
  }
})(app);
```

## RBAC Quick Use
Access the role service directly from your app instance:

```javascript
// Check permission
const allowed = await app.roleService.checkPermission('admin', 'users', 'delete');

// Create role
await app.roleService.createRole({
  name: 'editor',
  permissions: [{ resource: 'posts', actions: ['create', 'update'] }]
});
```

## Environment Variables
- `JWT_SECRET`: Secret key for signing tokens.
- `MONGO_URL`: MongoDB connection string.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`: SMTP configuration.
- `BASE_URL`: Base URL for email links.
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`: Google OAuth credentials.

## Troubleshooting
- **401 Unauthorized**: Check if `Authorization: Bearer <accessToken>` header is present and valid.
- **Password policy errors**: Ensure passwords meet length, uppercase, number, and special character requirements.
- **Email issues**: Verify SMTP configuration; features relying on email will automatically disable if SMTP is misconfigured.

## Error Codes
| Code | Description | HTTP Status |
| :--- | :--- | :--- |
| `AUTH_BAD_REQUEST` | Generic bad request error | 400 |
| `AUTH_VALIDATION` | Invalid request data | 400 |
| `AUTH_PASSWORD_POLICY` | Password policy violation | 400 |
| `AUTH_PASSWORD_REUSE` | Cannot reuse previous passwords | 400 |
| `AUTH_SOCIAL_FAILED` | Social login failure | 400 |
| `AUTH_INVALID_ID` | Invalid resource identifier | 400 |
| `AUTH_UNAUTHORIZED` | Authentication required | 401 |
| `AUTH_INVALID_CREDENTIALS` | Invalid email or password | 401 |
| `AUTH_INVALID_TOKEN` | Token invalid or missing | 401 |
| `AUTH_EXPIRED_TOKEN` | Token expired | 401 |
| `AUTH_2FA_FAILED` | Invalid 2FA code | 401 |
| `AUTH_FORBIDDEN` | Insufficient permissions | 403 |
| `AUTH_ACCOUNT_LOCKED` | Account locked due to failed attempts | 403 |
| `AUTH_EMAIL_NOT_VERIFIED` | Email verification required | 403 |
| `AUTH_2FA_REQUIRED` | 2FA code input required | 403 |
| `AUTH_NOT_FOUND` | Resource not found | 404 |
| `AUTH_CONFLICT` | Resource already exists | 409 |
| `AUTH_RATE_LIMITED` | Too many requests | 429 |
| `AUTH_SMTP_DISABLED` | Email delivery service disabled | 503 |
| `AUTH_INTERNAL` | Unexpected internal error | 500 |

## License
MIT © Dax Crafta
