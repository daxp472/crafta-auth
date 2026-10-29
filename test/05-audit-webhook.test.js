/**
 * 05 — Audit logging + webhooks
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const http = require('http');
const mongoose = require('mongoose');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;
let webhookServer;
let receivedWebhooks = [];

describe('05-audit-webhook', () => {
  before(async () => {
    webhookServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        try {
          receivedWebhooks.push({
            event: req.headers['x-crafta-event'],
            signature: req.headers['x-crafta-signature'],
            body: JSON.parse(body),
          });
        } catch {}
        res.writeHead(200);
        res.end('ok');
      });
    });
    await new Promise((r) => webhookServer.listen(0, r));
    const port = webhookServer.address().port;

    const app = buildApp({
      webhooks: {
        url: `http://127.0.0.1:${port}`,
        secret: 'test-secret',
        events: ['user.registered', 'user.login', 'user.logout'],
      },
      features: { auditLogs: true, webhooks: true },
    });
    server = await startApp();

    await req('POST', '/register', {
      name: 'Audit User',
      email: 'audit@example.com',
      password: 'Strong@Pass1',
    });
  });
  after(async () => {
    await stopApp();
    await new Promise((r) => webhookServer.close(r));
  });

  it('webhook fires on register with HMAC signature', async () => {
    const found = receivedWebhooks.find((w) => w.event === 'user.registered');
    assert.ok(found, `register webhook should fire. Got: ${JSON.stringify(receivedWebhooks)}`);
    assert.ok(found.signature, 'webhook should be signed');
    assert.strictEqual(found.body.data.email, 'audit@example.com');
  });

  it('audit log is written to MongoDB', async () => {
    require('../src/models/audit-log');
    const AuditLog = mongoose.model('AuditLog');
    const count = await AuditLog.countDocuments({ action: 'register' });
    assert.ok(count > 0, 'audit log entry for register should exist');
  });

  it('audit log has required enum actions', async () => {
    require('../src/models/audit-log');
    const AuditLog = mongoose.model('AuditLog');
    const actions = AuditLog.schema.path('action').enumValues;
    const required = ['login', 'logout', 'register', 'email_verify', '2fa_verify', 'refresh_token', 'social_login', 'backup_codes_generated', 'account_locked', 'password_reset', 'password_change', 'profile_update', 'role_change', '2fa_enabled', '2fa_disabled', 'password_reset_request'];
    for (const a of required) {
      assert.ok(actions.includes(a), `missing audit action: ${a}`);
    }
  });
});