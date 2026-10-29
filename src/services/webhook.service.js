// packages/auth/src/services/webhook.service.js
/**
 * WebhookService — fire HTTP callbacks for auth events so downstream
 * systems (CRM, analytics, SIEM) can react to registration, login, etc.
 *
 * Failures are swallowed (logged) so they never break auth flows.
 */
const https = require('https');
const http = require('http');
const URL = require('url');
const crypto = require('crypto');

class WebhookService {
  constructor(config = {}) {
    this.config = config;
    this.enabled = !!(config.webhooks && config.webhooks.url);
    this.url = this.enabled ? config.webhooks.url : null;
    this.secret = this.enabled ? config.webhooks.secret : null;
    this.events = this.enabled
      ? config.webhooks.events || ['user.registered', 'user.login', 'user.logout', 'user.password_changed']
      : [];
    this.deliveryStats = {
      total: 0,
      success: 0,
      failure: 0,
      lastEvent: null,
      lastStatus: null
    };
  }

  /**
   * Sign the payload with HMAC-SHA256 so receivers can verify authenticity.
   */
  sign(payload) {
    if (!this.secret) return null;
    return crypto
      .createHmac('sha256', this.secret)
      .update(payload)
      .digest('hex');
  }

  /**
   * Fire a webhook event. Non-blocking — failures are caught and returned,
   * never thrown.
   */
  async emit(event, data = {}) {
    if (!this.enabled) return { delivered: false, reason: 'webhooks_disabled' };
    if (this.events.length && !this.events.includes(event)) {
      return { delivered: false, reason: 'event_not_subscribed', event };
    }

    const body = JSON.stringify({
      event,
      timestamp: new Date().toISOString(),
      data
    });
    const signature = this.sign(body);

    const parsed = URL.parse(this.url);
    const transport = parsed.protocol === 'https:' ? https : http;

    return new Promise((resolve) => {
      const req = transport.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.path || '/',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            'X-Crafta-Event': event,
            ...(signature ? { 'X-Crafta-Signature': signature } : {})
          }
        },
        (res) => {
          let payload = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => (payload += chunk));
          res.on('end', () => {
            const success = res.statusCode >= 200 && res.statusCode < 300;
            this.deliveryStats.total++;
            if (success) {
              this.deliveryStats.success++;
            } else {
              this.deliveryStats.failure++;
            }
            this.deliveryStats.lastEvent = event;
            this.deliveryStats.lastStatus = res.statusCode;

            resolve({
              delivered: success,
              status: res.statusCode,
              body: payload.slice(0, 500)
            });
          });
        }
      );

      req.on('error', (err) => {
        this.deliveryStats.total++;
        this.deliveryStats.failure++;
        this.deliveryStats.lastEvent = event;
        this.deliveryStats.lastStatus = 'error';

        resolve({ delivered: false, reason: err.message });
      });

      req.setTimeout(5000, () => {
        req.destroy();
        resolve({ delivered: false, reason: 'request_timeout' });
      });

      req.write(body);
      req.end();
    });
  }

  /**
   * Returns delivery monitoring statistics.
   */
  getDeliveryStatus() {
    const rate = this.deliveryStats.total > 0
      ? (this.deliveryStats.success / this.deliveryStats.total) * 100
      : 0;

    return {
      ...this.deliveryStats,
      successRate: `${rate.toFixed(2)}%`
    };
  }
}

module.exports = WebhookService;