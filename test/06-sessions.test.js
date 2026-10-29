/**
 * 06 — Session management
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;

describe('06-sessions', () => {
  before(async () => {
    const app = buildApp({ session: { maxSessions: 3, sessionExpiryMs: 30 * 24 * 60 * 60 * 1000 } });
    server = await startApp();
    await req('POST', '/register', {
      name: 'Session User',
      email: 'session@example.com',
      password: 'Strong@Pass1',
    });
  });
  after(async () => { await stopApp(); });

  it('logout-all invalidates all sessions', async () => {
    const l1 = await req('POST', '/login', { email: 'session@example.com', password: 'Strong@Pass1' });
    const l2 = await req('POST', '/login', { email: 'session@example.com', password: 'Strong@Pass1' });

    const res = await req('POST', '/logout-all', {}, {
      Authorization: `Bearer ${l1.body.accessToken}`,
    });
    assert.strictEqual(res.status, 200, `expected 200, got ${res.status} ${JSON.stringify(res.body)}`);

    const p1 = await req('PUT', '/profile', { name: 'X' }, { Authorization: `Bearer ${l1.body.accessToken}` });
    const p2 = await req('PUT', '/profile', { name: 'X' }, { Authorization: `Bearer ${l2.body.accessToken}` });
    assert.strictEqual(p1.status, 401, 'session 1 token should be dead');
    assert.strictEqual(p2.status, 401, 'session 2 token should be dead');
  });
});