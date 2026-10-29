/**
 * 01 — Register, login, refresh, logout, profile
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;

describe('01-register-login', () => {
  before(async () => {
    const app = buildApp();
    server = await startApp();
  });
  after(async () => { await stopApp(); });

  it('register creates a user', async () => {
    const res = await req('POST', '/register', {
      name: 'Test User',
      email: 'alice@example.com',
      password: 'Strong@Pass1',
    });
    assert.strictEqual(res.status, 201, `expected 201, got ${res.status} ${JSON.stringify(res.body)}`);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.message, 'Registration successful');
  });

  it('register rejects duplicate email', async () => {
    const res = await req('POST', '/register', {
      name: 'Dup User',
      email: 'alice@example.com',
      password: 'Strong@Pass1',
    });
    assert.strictEqual(res.status, 409, `expected 409, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_CONFLICT');
  });

  it('register rejects weak password', async () => {
    const res = await req('POST', '/register', {
      name: 'Weak User',
      email: 'weak@example.com',
      password: 'abc',
    });
    assert.strictEqual(res.status, 400, `expected 400, got ${res.status}`);
    assert.ok(res.body.error || res.body.code, 'should have error message');
  });

  it('login succeeds with valid creds', async () => {
    const res = await req('POST', '/login', {
      email: 'alice@example.com',
      password: 'Strong@Pass1',
    });
    assert.strictEqual(res.status, 200, `expected 200, got ${res.status}`);
    assert.ok(res.body.accessToken);
    assert.ok(res.body.refreshToken);
  });

  it('login rejects wrong password', async () => {
    const res = await req('POST', '/login', {
      email: 'alice@example.com',
      password: 'Wrong@Pass1',
    });
    assert.strictEqual(res.status, 401, `expected 401, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_INVALID_CREDENTIALS');
  });

  it('login rejects unknown email', async () => {
    const res = await req('POST', '/login', {
      email: 'nobody@example.com',
      password: 'Strong@Pass1',
    });
    assert.strictEqual(res.status, 401, `expected 401, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_INVALID_CREDENTIALS');
  });

  it('refresh token rotates and old token is invalidated', async () => {
    const login = await req('POST', '/login', {
      email: 'alice@example.com',
      password: 'Strong@Pass1',
    });
    const oldRefresh = login.body.refreshToken;

    const refresh = await req('POST', '/refresh-token', { refreshToken: oldRefresh });
    assert.strictEqual(refresh.status, 200, `expected 200, got ${refresh.status}`);
    assert.ok(refresh.body.accessToken);
    assert.notStrictEqual(refresh.body.refreshToken, oldRefresh, 'refresh token should rotate');

    // Old token must be rejected
    const reuse = await req('POST', '/refresh-token', { refreshToken: oldRefresh });
    assert.strictEqual(reuse.status, 401, `old refresh token should be rejected, got ${reuse.status}`);
    assert.strictEqual(reuse.body.code, 'AUTH_INVALID_TOKEN');
  });

  it('protected profile returns user data with valid token', async () => {
    const login = await req('POST', '/login', {
      email: 'alice@example.com',
      password: 'Strong@Pass1',
    });
    const res = await req('PUT', '/profile', { name: 'Test User Updated' }, {
      Authorization: `Bearer ${login.body.accessToken}`,
    });
    assert.strictEqual(res.status, 200, `expected 200, got ${res.status} ${JSON.stringify(res.body)}`);
    assert.strictEqual(res.body.user.email, 'alice@example.com');
  });

  it('protected route rejects missing token', async () => {
    const res = await req('PUT', '/profile', { name: 'X' });
    assert.strictEqual(res.status, 401, `expected 401, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_UNAUTHORIZED');
  });

  it('protected route rejects invalid token', async () => {
    const res = await req('PUT', '/profile', { name: 'X' }, {
      Authorization: 'Bearer not-a-real-token',
    });
    assert.strictEqual(res.status, 401, `expected 401, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_INVALID_TOKEN');
  });

  it('logout revokes refresh token', async () => {
    const login = await req('POST', '/login', {
      email: 'alice@example.com',
      password: 'Strong@Pass1',
    });
    const logout = await req('POST', '/logout', { refreshToken: login.body.refreshToken }, {
      Authorization: `Bearer ${login.body.accessToken}`,
    });
    assert.strictEqual(logout.status, 200, `expected 200, got ${logout.status} ${JSON.stringify(logout.body)}`);

    // Refresh token should now be dead
    const after = await req('POST', '/refresh-token', { refreshToken: login.body.refreshToken });
    assert.strictEqual(after.status, 401, `expected 401 after logout, got ${after.status}`);
  });
});