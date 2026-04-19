# @dax-crafta/auth

Production-ready auth for Crafta apps with plug-and-play defaults and clean JSON customization.

[![npm version](https://img.shields.io/npm/v/@dax-crafta/auth.svg)](https://www.npmjs.com/package/@dax-crafta/auth)
[![License](https://img.shields.io/npm/l/@dax-crafta/auth.svg)](https://github.com/daxp472/crafta/blob/main/LICENSE)
[![Downloads](https://img.shields.io/npm/dm/@dax-crafta/auth.svg)](https://www.npmjs.com/package/@dax-crafta/auth)

## Why this package

- You should not rebuild auth from scratch for every project.
- This package gives you login, refresh tokens, password reset, RBAC, 2FA, audit logs, and feature toggles out of the box.
- Keep defaults for speed, customize only where needed.

## What you get

- JWT auth with refresh token rotation
- Register, login, verify, forgot/reset password routes
- Optional 2FA (TOTP + backup codes)
- RBAC with role and permission service
- Route-level rate limiting
- Password policy and password history checks
- Optional Google OAuth
- Audit logs (Mongo + file)

## 1. Install

```bash
npm install crafta @dax-crafta/auth
```

## 2. Minimal setup (copy-paste)

Create `server.js`:

```js
const { crafta } = require('crafta');
const { auth } = require('@dax-crafta/auth');

const app = crafta();

auth({
  env: {
    JWT_SECRET: process.env.JWT_SECRET || 'dev-secret-123'
  },
  mongoUrl: process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/crafta-auth-demo',

  // Local dev ke liye simple mode
  features: {
    emailVerification: false,
    loginAlerts: false,
    csrf: false
  }
})(app);

app.get('/health', (req, res) => {
  res.json({ ok: true, message: 'Auth is running' });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

Run it:

```bash
node server.js
```

## 3. First Postman test flow

### Health
- `GET /health`

### Register
- `POST /register`

```json
{
  "name": "Test User",
  "email": "testuser1@example.com",
  "password": "Strong@1234"
}
```

### Login
- `POST /login`

```json
{
  "email": "testuser1@example.com",
  "password": "Strong@1234"
}
```

Use returned `accessToken` on protected routes:
- `Authorization: Bearer <token>`

### Profile (protected)
- `PUT /profile`

```json
{
  "name": "Updated Name"
}
```

### Refresh token
- `POST /refresh-token`

```json
{
  "refreshToken": "<token-from-login>"
}
```

## 4. Customize with JSON (main power)

Everything is controlled from one config object.

```js
auth({
  strategy: 'jwt',
  fields: ['name', 'email', 'password', 'age'],

  routes: {
    register: '/api/auth/register',
    login: '/api/auth/login',
    verify: '/api/auth/verify',
    forgotPassword: '/api/auth/forgot-password',
    resetPassword: '/api/auth/reset-password',
    refreshToken: '/api/auth/refresh-token',
    profile: '/api/auth/profile',
    twoFactor: '/api/auth/2fa'
  },

  passwordPolicy: {
    minLength: 10,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    expiryDays: 90,
    minStrength: 3
  },

  limits: {
    loginMax: 10,
    twoFAMax: 20,
    forgotPasswordMax: 5,
    refreshMax: 30
  }
})(app);
```

## 5. Feature toggles (fast on/off)

Set any feature to `false` and it turns off.

```js
auth({
  features: {
    emailVerification: false,
    loginAlerts: false,
    securityAttempts: true,
    rateLimit: true,
    auditLogs: true,
    twoFactor: true,
    csrf: false
  }
})(app);
```

Notes:
- If SMTP is missing, emailVerification/loginAlerts are auto-disabled with warning.
- If `securityAttempts: false`, lockout attempt handling is disabled.

## 6. Email setup (optional)

Enable this only when SMTP is ready:

```js
auth({
  features: {
    emailVerification: true,
    loginAlerts: true
  },
  smtp: {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    from: process.env.SMTP_FROM
  },
  baseUrl: process.env.BASE_URL || 'http://localhost:3000'
})(app);
```

## 7. Google OAuth setup (optional)

```js
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

Routes:
- `GET /auth/google`
- `GET /auth/google/callback`

## 8. RBAC quick use

```js
const role = await app.roleService.createRole({
  name: 'admin',
  permissions: [
    { resource: 'users', actions: ['create', 'read', 'update', 'delete'] }
  ]
});

const allowed = await app.roleService.checkPermission('admin', 'users', 'delete');
```

## 9. Environment variables

```bash
JWT_SECRET=my-super-secret
MONGO_URL=mongodb://127.0.0.1:27017/crafta-auth-demo
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=you@example.com
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com
BASE_URL=http://localhost:3000
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

## 10. Troubleshooting

- 401 on protected route
  - Token missing or expired.
  - Send `Authorization: Bearer <accessToken>`.

- Register fails on password policy
  - Use uppercase + lowercase + number + special char.

- Email not sending
  - Check SMTP credentials and port.
  - If SMTP absent, email features auto-disable by design.

- Refresh token invalid
  - Refresh token is rotated; use latest token returned by API.

## 11. Release confidence

- Built-in smoke suite is available:

```bash
npm test
```

## License

MIT © Dax Crafta