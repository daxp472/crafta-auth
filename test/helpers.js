/**
 * Test helpers — shared setup for the live integration suite.
 * Starts an Express server with @dax-crafta/auth against a real MongoDB.
 */
const mongoose = require('mongoose');
const express = require('express');
const cookieParser = require('cookie-parser');
const { auth, ApiError } = require('../src/index');

const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/crafta-auth-test';

let server = null;
let app = null;

async function connectMongo() {
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(MONGO_URL);
  }
  // Wipe test collections for a clean slate
  const cols = Object.keys(mongoose.connection.collections);
  for (const name of cols) {
    await mongoose.connection.collections[name].deleteMany({});
  }
}

async function disconnectMongo() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
}

function buildApp(overrides = {}) {
  app = express();
  app.use(express.json());
  app.use(cookieParser());

  auth({
    mongoUrl: MONGO_URL,
    env: { JWT_SECRET: 'test-secret-256-bits-long-key' },
    features: {
      emailVerification: false,
      loginAlerts: false,
      csrf: false,
      rateLimit: false,
      auditLogs: true,
      twoFactor: true,
      passwordless: false,
      webhooks: true,
    },
    session: { maxSessions: 3, sessionExpiryMs: 30 * 24 * 60 * 60 * 1000 },
    webhooks: {
      secret: 'test-webhook-secret',
      events: ['user.registered', 'user.login', 'user.logout'],
    },
    ...overrides,
  })(app);

  // Ensure MongoDB connection is established before returning, and models are registered.
  // auth() connects async; without this the first test hits a duplicate-key
  // error because the connection isn't ready when the request fires.
  global.__resetDb = async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(MONGO_URL);
    }
    // Ensure models are registered by requiring user and audit-log models
    try { require('../src/models/user'); } catch (e) {}
    try { require('../src/models/audit-log'); } catch (e) {}

    const cols = Object.keys(mongoose.connection.collections);
    for (const name of cols) {
      try {
        await mongoose.connection.collections[name].drop();
      } catch (e) {
        // Collection may not exist yet — ignore
      }
    }
  };

  return app;
}

function startApp(port = 0) {
  return new Promise((resolve) => {
    server = app.listen(port, () => {
      resolve(server);
    });
  });
}

async function stopApp() {
  if (server) {
    await new Promise((r) => server.close(r));
    server = null;
  }
}

// ── HTTP helpers ──
const BASE = () => `http://127.0.0.1:${server.address().port}`;

async function req(method, path, body, headers = {}) {
  const url = `${BASE()}${path}`;
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
  };
  // GET/HEAD requests cannot have a body per fetch spec
  if (body !== undefined && !['GET', 'HEAD'].includes(method)) {
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  let json = null;
  let text = null;
  const clone = res.clone();
  try {
    json = await res.json();
  } catch {
    text = await clone.text();
  }
  return { status: res.status, body: json, text };
}

module.exports = {
  connectMongo,
  disconnectMongo,
  buildApp,
  startApp,
  stopApp,
  req,
  ApiError,
};