/**
 * 02 — Password reset flow + forgot password
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;

describe('02-password-reset', () => {
  before(async () => {
    const app = buildApp();
    server = await startApp();
    await req('POST', '/register', {
      name: 'Bob Reset',
      email: 'bob@example.com',
      password: 'Strong@Pass1',
    });
  });
  after(async () => { await stopApp(); });

  it('forgot-password returns 200 even for unknown email', async () => {
    const res = await req('POST', '/forgot-password', { email: 'ghost@example.com' });
    assert.strictEqual(res.status, 200, `expected 200, got ${res.status}`);
    assert.strictEqual(res.body.success, true);
  });

  it('reset-password rejects invalid token', async () => {
    const res = await req('POST', '/reset-password', {
      token: 'invalid-token',
      newPassword: 'New@Pass1',
    });
    assert.strictEqual(res.status, 400, `expected 400, got ${res.status}`);
    assert.ok(res.body.code, 'should have error code');
  });

  it('reset-password rejects weak new password', async () => {
    const res = await req('POST', '/reset-password', {
      token: 'some-token',
      newPassword: 'weak',
    });
    assert.strictEqual(res.status, 400, `expected 400, got ${res.status}`);
    assert.ok(res.body.error || res.body.code, 'should have error message');
  });

  it('reset-password rejects missing token', async () => {
    const res = await req('POST', '/reset-password', { newPassword: 'New@Pass1' });
    assert.strictEqual(res.status, 400, `expected 400, got ${res.status}`);
  });
});