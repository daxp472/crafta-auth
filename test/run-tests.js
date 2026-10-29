/**
 * Test runner — runs all test/*.test.js files sequentially.
 * Each test file uses the tiny-test framework (describe/it/before/after).
 *
 * IMPORTANT: helpers and tiny-test are NEVER cleared from cache between
 * test files, because helpers registers Mongoose models via auth().
 * Only the test file itself is cleared.
 */
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');

const testDir = __dirname;
const files = fs
  .readdirSync(testDir)
  .filter((f) => f.endsWith('.test.js') && !f.startsWith('run-') && !f.startsWith('tiny-'))
  .sort();

const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/crafta-auth-test';

// Register Mongoose models eagerly so they exist before any test file runs.
// auth() normally does this lazily, but the DB reset happens BEFORE auth()
// is called in each test file's before() hook.
require('./helpers'); // triggers require chain that registers models
require('../src/models/user');
require('../src/models/audit-log');

async function resetMongoose() {
  // Connect once and keep the connection — disconnecting invalidates
  // the mongoose models registered by auth().
  if (mongoose.connection.readyState === 0) {
    await mongoose.connect(MONGO_URL);
  }
  // Drop every collection known to the MongoDB server.
  // We use db.listCollections() rather than mongoose.connection.collections
  // because the latter only tracks collections touched through Mongoose models,
  // which is empty until auth() runs (after this reset).
  const cols = await mongoose.connection.db.listCollections().toArray();
  for (const col of cols) {
    try {
      await mongoose.connection.db.dropCollection(col.name);
    } catch (e) {
      // Collection may not exist yet — ignore
    }
  }
}

async function run() {
  let totalPassed = 0;
  let totalFailed = 0;
  const failures = [];

  for (const file of files) {
    const filePath = path.join(testDir, file);
    console.log(`\n=== ${file} ===`);

    // Only clear the test file's own cache — keep helpers and tiny-test cached
    // so Mongoose models registered by auth() stay registered.
    const resolved = require.resolve(filePath);
    delete require.cache[resolved];

    try {
      await resetMongoose();
      require(filePath);
      const tinyTest = require('./tiny-test');
      await tinyTest.runPending();

      const stats = tinyTest.getStats();
      totalPassed += stats.passed;
      totalFailed += stats.failed;
      failures.push(...stats.failures);
    } catch (err) {
      console.error(`[FAIL] ${file}: ${err.message}`);
      if (err.stack) console.error(err.stack.split('\n').slice(1, 6).join('\n'));
      totalFailed += 1;
      failures.push({ name: file, err });
    }
  }

  console.log(`\nSummary: ${totalPassed} passed, ${totalFailed} failed`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    failures.forEach((f) => console.log(`  - ${f.name}: ${f.err.message}`));
  }

  if (totalFailed > 0) {
    process.exitCode = 1;
  }
}

run().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});