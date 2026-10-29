/**
 * 09 — Passwordless magic link
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;

describe('09-passwordless', () => {
  before(async () => {
    const app = buildApp({
      features: { passwordless: true, emailVerification: false, loginAlerts: false },
      smtp: {
        host: 'smtp.example.com',
        port: 587,
        auth: { user: 'test', pass: 'test' },
        from: 'noreply@example.com',
      },
    });
    server = await startApp();
    await req('POST', '/register', {
      name: 'Magic User',
      email: 'magic@example.com',
      password: 'Strong@Pass1',
    });
  });
  after(async () => { await stopApp(); });

  it('magic link request returns 200 (no oracle)', async () => {
    const res = await req('POST', '/auth/magic-link', { email: 'ghost@example.com' });
    assert.strictEqual(res.status, 200, `expected 200, got ${res.status}`);
  });

  it('magic link verify rejects invalid token', async () => {
    const res = await req('GET', '/auth/magic-link/verify?token=invalid');
    assert.strictEqual(res.status, 401, `expected 401, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_INVALID_TOKEN');
  });
});