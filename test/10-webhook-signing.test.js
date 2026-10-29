/**
 * 10 — Webhook service: signing, event filtering, delivery
 */
const { describe, it } = require('./tiny-test');
const assert = require('assert');
const WebhookService = require('../src/services/webhook.service');

describe('10-webhook-signing', () => {
  it('sign returns HMAC-SHA256 hex when secret is set', () => {
    const svc = new WebhookService({ webhooks: { url: 'http://example.com', secret: 's3cr3t' } });
    const sig = svc.sign('hello');
    assert.strictEqual(typeof sig, 'string');
    assert.strictEqual(sig.length, 64, 'HMAC-SHA256 hex digest is 64 chars');
  });

  it('sign returns null when no secret', () => {
    const svc = new WebhookService({ webhooks: { url: 'http://example.com' } });
    assert.strictEqual(svc.sign('hello'), null);
  });

  it('emit is a no-op when webhooks disabled', async () => {
    const svc = new WebhookService({});
    const result = await svc.emit('login', { userId: 'u1' });
    assert.strictEqual(result.delivered, false);
    assert.strictEqual(result.reason, 'webhooks_disabled');
  });

  it('emit filters events not subscribed', async () => {
    const svc = new WebhookService({
      webhooks: { url: 'http://example.com', secret: 's3cr3t', events: ['login'] },
    });
    const result = await svc.emit('logout', { userId: 'u1' });
    assert.strictEqual(result.delivered, false);
    assert.strictEqual(result.reason, 'event_not_subscribed');
    assert.strictEqual(result.event, 'logout');
  });
});