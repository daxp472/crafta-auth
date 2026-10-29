/**
 * 03 — 2FA / MFA flow
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const mongoose = require('mongoose');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;

describe('03-2fa', () => {
  before(async () => {
    const app = buildApp();
    server = await startApp();
    // Register user
    await req('POST', '/register', {
      name: 'Two FA User',
      email: 'two@example.com',
      password: 'Strong@Pass1',
    });
    // Enable 2FA directly by setting twoFactorSecret and twoFactorEnabled
    require('../src/models/user');
    const User = mongoose.model('User');
    const crypto = require('crypto');
    const secret = crypto.randomBytes(20).toString('hex');
    await User.findOneAndUpdate(
      { email: 'two@example.com' },
      { twoFactorSecret: secret, twoFactorEnabled: true }
    );
  });
  after(async () => { await stopApp(); });

  it('2fa verify rejects missing code', async () => {
    require('../src/models/user');
    const User = mongoose.model('User');
    const user = await User.findOne({ email: 'two@example.com' });
    const res = await req('POST', '/2fa', { userId: user._id });
    assert.strictEqual(res.status, 400, `expected 400, got ${res.status}`);
  });

  it('2fa verify rejects unknown user', async () => {
    const res = await req('POST', '/2fa', { userId: '000000000000000000000000', code: '123456' });
    assert.strictEqual(res.status, 404, `expected 404, got ${res.status}`);
  });

  it('2fa verify rejects invalid code', async () => {
    require('../src/models/user');
    const User = mongoose.model('User');
    const user = await User.findOne({ email: 'two@example.com' });
    const res = await req('POST', '/2fa', { userId: user._id, code: '000000' });
    assert.strictEqual(res.status, 401, `expected 401, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_2FA_FAILED');
  });
});