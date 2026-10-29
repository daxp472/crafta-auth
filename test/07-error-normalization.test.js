/**
 * 07 — Error normalization + standardized error codes
 */
const { describe, it } = require('./tiny-test');
const assert = require('assert');
const ApiError = require('../src/utils/api-error');

describe('07-error-normalization', () => {
  it('has all 19 factory methods', () => {
    const methods = [
      'unauthorized', 'forbidden', 'notFound', 'validation', 'badRequest',
      'conflict', 'tooManyRequests', 'accountLocked', 'invalidCredentials',
      'invalidToken', 'expiredToken', 'emailNotVerified', 'twoFactorRequired',
      'twoFactorFailed', 'passwordPolicy', 'passwordReuse', 'smtpDisabled',
      'socialAuthFailed', 'internal'
    ];
    for (const m of methods) {
      assert.strictEqual(typeof ApiError[m], 'function', `ApiError.${m} should be a function`);
      const err = ApiError[m]();
      assert.ok(err instanceof ApiError, `${m} should return ApiError instance`);
      assert.ok(err.code, `${m} should set a code`);
      assert.ok(err.status, `${m} should set a status`);
    }
  });

  it('normalize converts Mongoose ValidationError', () => {
    const err = { name: 'ValidationError', message: 'bad', errors: { email: { message: 'x' } } };
    const normalized = ApiError.normalize(err);
    assert.strictEqual(normalized.code, 'AUTH_VALIDATION');
    assert.strictEqual(normalized.status, 400);
  });

  it('normalize converts JWT errors', () => {
    const expired = ApiError.normalize({ name: 'TokenExpiredError', message: 'expired' });
    assert.strictEqual(expired.code, 'AUTH_EXPIRED_TOKEN');
    const invalid = ApiError.normalize({ name: 'JsonWebTokenError', message: 'bad' });
    assert.strictEqual(invalid.code, 'AUTH_INVALID_TOKEN');
  });

  it('normalize converts duplicate key 11000', () => {
    const dup = ApiError.normalize({ code: 11000, message: 'dup', keyValue: { email: 'a@b.com' } });
    assert.strictEqual(dup.code, 'AUTH_CONFLICT');
  });

  it('normalize converts generic Error', () => {
    const gen = ApiError.normalize(new Error('boom'));
    assert.strictEqual(gen.code, 'AUTH_INTERNAL');
    assert.strictEqual(gen.status, 500);
  });

  it('normalize passes through ApiError unchanged', () => {
    const orig = ApiError.forbidden('nope');
    const same = ApiError.normalize(orig);
    assert.strictEqual(same, orig);
  });

  it('error response shape has success:false + code + error', () => {
    const err = ApiError.unauthorized('need token');
    const json = { success: false, code: err.code, error: err.message };
    assert.strictEqual(json.success, false);
    assert.strictEqual(json.code, 'AUTH_UNAUTHORIZED');
    assert.strictEqual(json.error, 'need token');
  });
});