/**
 * Tiny test harness — supports describe()/it() with async assertions.
 * Drop-in replacement for the mocha BDD interface. No dependencies.
 */
const assert = require('assert');

let passed = 0;
let failed = 0;
const failures = [];
let pendingTests = [];

function describe(name, fn) {
  console.log(`\n  ${name}`);
  fn();
}

function it(name, fn) {
  pendingTests.push({ name, fn });
}

async function runPending() {
  // Reset DB BEFORE before() so test data created in before() survives.
  // Also ensures MongoDB connection is established (auth() connects async).
  if (global.__resetDb) { await global.__resetDb(); }

  // Run before hooks — this is where buildApp() registers Mongoose models
  if (global.__before) { await global.__before(); }

  for (const test of pendingTests) {
    try {
      await test.fn();
      console.log(`    ✓ ${test.name}`);
      passed += 1;
    } catch (err) {
      console.log(`    ✗ ${test.name}`);
      console.log(`      ${err.message}`);
      failures.push({ name: test.name, err });
      failed += 1;
    }
  }
  if (global.__after) { await global.__after(); }

  // Reset for next file
  pendingTests = [];
  global.__before = null;
  global.__after = null;
  global.__resetDb = null;
}

function before(fn) {
  global.__before = fn;
}

function after(fn) {
  global.__after = fn;
}

function getStats() {
  return { passed, failed, failures };
}

function resetStats() {
  passed = 0;
  failed = 0;
  failures.length = 0;
}

module.exports = { describe, it, before, after, runPending, getStats, resetStats };