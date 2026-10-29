/**
 * 04 — RBAC: roles + permissions
 */
const { describe, it, before, after } = require('./tiny-test');
const assert = require('assert');
const mongoose = require('mongoose');
const { buildApp, startApp, stopApp, req } = require('./helpers');

let server;

describe('04-rbac', () => {
  before(async () => {
    const app = buildApp();
    server = await startApp();
    await req('POST', '/register', {
      name: 'Admin User',
      email: 'admin@example.com',
      password: 'Strong@Pass1',
    });
    require('../src/models/user');
    const User = mongoose.model('User');
    await User.findOneAndUpdate({ email: 'admin@example.com' }, { role: 'admin' });
  });
  after(async () => { await stopApp(); });

  it('create role succeeds as admin', async () => {
    const login = await req('POST', '/login', {
      email: 'admin@example.com',
      password: 'Strong@Pass1',
    });
    const res = await req('POST', '/roles', {
      name: 'editor',
      permissions: [{ resource: 'posts', actions: ['create', 'read'] }],
    }, { Authorization: `Bearer ${login.body.accessToken}` });
    assert.strictEqual(res.status, 201, `expected 201, got ${res.status} ${JSON.stringify(res.body)}`);
    assert.strictEqual(res.body.role.name, 'editor');
  });

  it('reject duplicate role name', async () => {
    const login = await req('POST', '/login', {
      email: 'admin@example.com',
      password: 'Strong@Pass1',
    });
    const res = await req('POST', '/roles', {
      name: 'editor',
      permissions: [],
    }, { Authorization: `Bearer ${login.body.accessToken}` });
    assert.strictEqual(res.status, 409, `expected 409, got ${res.status}`);
    assert.strictEqual(res.body.code, 'AUTH_CONFLICT');
  });
});