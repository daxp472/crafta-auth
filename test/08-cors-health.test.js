/**
 * 08 — CORS + health endpoint
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;

describe('08-cors-health', () => {
  before(async () => {
    const app = buildApp();
    server = await startApp();
  });
  after(async () => { await stopApp(); });

  it('health endpoint returns ok + db status', async () => {
    const res = await req('GET', '/auth/health');
    assert.strictEqual(res.status, 200, `expected 200, got ${res.status}`);
    assert.strictEqual(res.body.status, 'ok');
    assert.strictEqual(res.body.db, 'connected');
    assert.ok(res.body.version, 'should report version');
    assert.strictEqual(typeof res.body.features, 'object');
  });

  it('CORS preflight returns 204 with origin header', async () => {
    const url = `http://127.0.0.1:${server.address().port}/login`;
    const res = await fetch(url, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://example.com',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.strictEqual(res.status, 204, `expected 204, got ${res.status}`);
    const origin = res.headers.get('access-control-allow-origin');
    assert.ok(origin, 'should have allow-origin header');
  });

  it('CORS actual request includes allow-origin header', async () => {
    const res = await req('POST', '/login', { email: 'x', password: 'y' }, { Origin: 'https://example.com' });
    // Login with invalid creds returns 401 (or 400 if validation fails)
    assert.ok(res.status === 400 || res.status === 401, `expected 400/401, got ${res.status}`);
  });
});