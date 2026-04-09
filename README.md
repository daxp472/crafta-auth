# @dax-crafta/auth

A powerful, flexible, and secure authentication system for Node.js applications. Built with enterprise-grade security features while maintaining developer-friendly simplicity.

[![npm version](https://img.shields.io/npm/v/@dax-crafta/auth.svg)](https://www.npmjs.com/package/@dax-crafta/auth)
[![License](https://img.shields.io/npm/l/@dax-crafta/auth.svg)](https://github.com/daxp472/crafta/blob/main/LICENSE)
[![Downloads](https://img.shields.io/npm/dm/@dax-crafta/auth.svg)](https://www.npmjs.com/package/@dax-crafta/auth)

## Features

- 🔐 **Comprehensive Authentication**
  - Email/Password authentication
  - Social login (Google, Facebook, GitHub)
  - JWT-based session management
  - Refresh token rotation

- 👥 **Advanced Role-Based Access Control (RBAC)**
  - Custom role creation
  - Granular permissions
  - Resource-based access control
  - Role hierarchy support

- 🔒 **Enterprise Security**
  - Multi-factor authentication (MFA/2FA)
  - Password policies and strength validation
  - Account lockout protection
  - Brute force prevention

- 📧 **Email Features**
  - Email verification
  - Password reset
  - Login notifications
  - Custom email templates

- 📝 **Audit Logging**
  - Detailed activity tracking
  - Security event logging
  - User session monitoring

## Quick Start

```bash
npm install @dax-crafta/auth
```

```javascript
const { crafta } = require('crafta');
const { auth } = require('@dax-crafta/auth');

const app = crafta();

// Basic setup
auth({
  strategy: 'jwt',
  fields: ['email', 'password'],
  // Works even without SMTP in local dev.
  // Email flows auto-disable if SMTP is not configured.
  emailVerification: true
})(app);

app.listen(3000);
```

## Feature Toggles (Simple JSON)

Disable any feature by setting it to `false`:

```javascript
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

Example: if `securityAttempts: false`, login-attempt lock handling and lock emails are disabled.

## Configuration

```javascript
auth({
  // Authentication Strategy
  strategy: 'jwt',
  
  // User Fields
  fields: ['name', 'email', 'password', 'age'],
  
  // Routes Configuration
  routes: {
    register: '/register',
    login: '/login',
    verify: '/verify',
    forgotPassword: '/forgot-password',
    resetPassword: '/reset-password',
    refreshToken: '/refresh-token',
    profile: '/profile',
    twoFactor: '/2fa'
  },
  
  // Security Settings
  maxLoginAttempts: 5,
  emailVerification: true,
  loginAlerts: true,
  
  // Password Policy
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    expiryDays: 90
  },
  
  // Email Configuration
  smtp: {
    host: 'smtp.example.com',
    port: 587,
    auth: {
      user: 'your-email@example.com',
      pass: 'your-password'
    },
    from: 'noreply@example.com'
  },
  
  // Social Login
  social: {
    google: {
      clientID: 'your-client-id',
      clientSecret: 'your-client-secret',
      callbackURL: 'http://localhost:3000/auth/google/callback'
    }
  }
})(app);
```

## Role-Based Access Control

```javascript
// Create a custom role
const adminRole = await roleService.createRole({
  name: 'admin',
  permissions: [{
    resource: 'users',
    actions: ['create', 'read', 'update', 'delete']
  }]
});

// Check permissions
const canAccess = await roleService.checkPermission('admin', 'users', 'create');
```

## Multi-Factor Authentication

```javascript
// Enable 2FA for a user
const { secret, qrCode } = await mfaService.generateSecret(
  'user@example.com',
  'MyApp'
);

// Verify 2FA token
const isValid = mfaService.verifyToken(token, secret);
```

## Audit Logging

```javascript
// Log user activity
await auditService.logActivity({
  userId: user.id,
  action: 'login',
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
  status: 'success'
});

// Get user activity history
const activities = await auditService.getUserActivity(userId);
```

## Security Best Practices

- Use HTTPS in production
- Set secure cookie options
- Configure CORS appropriately
- Regularly rotate refresh tokens
- Monitor failed login attempts
- Implement rate limiting

## License

MIT © Dax Crafta