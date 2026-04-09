// packages/auth/src/models/auditLog.js
const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false // allow anonymous actions (e.g., failed login by unknown user)
  },
  action: {
    type: String,
    required: true,
    enum: [
      'login',
      'logout',
      'password_change',
      'profile_update',
      'role_change',
      '2fa_enabled',
      '2fa_disabled',
      '2fa_verify',
      'register',
      'password_reset_request',
      'password_reset',
      'email_verify',
      'account_locked',
      'refresh_token',
      'backup_codes_generated',
      'social_login'
    ]
  },
  ipAddress: { type: String, default: '' },
  userAgent: { type: String, default: '' },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  status: {
    type: String,
    enum: ['success', 'failure'],
    required: true
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
}, { timestamps: false });

// Index for querying recent logs quickly
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ userId: 1, timestamp: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
