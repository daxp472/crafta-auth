// packages/auth/src/utils/email.js
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const ApiError = require('./api-error');

class EmailService {
  constructor(config) {
    this.config = config;
    this.baseUrl = (config && config.baseUrl) || '';
    this.smtpEnabled = !!(
      config.smtp &&
      config.smtp.host &&
      config.smtp.port &&
      config.smtp.auth &&
      config.smtp.auth.user &&
      config.smtp.auth.pass &&
      config.smtp.from
    );
    this.transporter = this.smtpEnabled ? nodemailer.createTransport(config.smtp) : null;
    this.from = this.smtpEnabled ? config.smtp.from : 'noreply@localhost';
    this.templateDir = config.emailTemplateDir || path.join(process.cwd(), "templates/email");
  }

  // Build a safe absolute URL from a base and a path, avoiding double slashes
  // or `undefined/...` when baseUrl is missing.
  joinUrl(base, urlPath) {
    let b = (base == null ? '' : String(base)).trim();
    if (b && b !== '/' && b.endsWith('/')) b = b.slice(0, -1);
    let p = (urlPath == null ? '' : String(urlPath)).trim();
    if (!p) p = '/';
    if (!p.startsWith('/')) p = '/' + p;
    return `${b}${p}`;
  }

  // Reusable sender
  async send({ to, subject, html, text }) {
    if (!this.smtpEnabled) {
      throw ApiError.smtpDisabled('Email delivery is not configured. Configure smtp in auth config.');
    }

    try {
      await this.transporter.sendMail({
        from: this.from,
        to,
        subject,
        html,
        text: text || html.replace(/<[^>]+>/g, '')
      });
      return { sent: true };
    } catch (err) {
      console.error("Email send error:", err);
      return { sent: false, reason: err.message };
    }
  }

  // Load an HTML template safely
  loadTemplate(name, variables = {}) {
    const filePath = path.join(this.templateDir, `${name}.html`);
    if (!fs.existsSync(filePath)) return null;

    let content = fs.readFileSync(filePath, "utf8");

    // Replace {{variable}} using a safer approach
    for (const [key, value] of Object.entries(variables)) {
      const regex = new RegExp(`{{\\s*${key}\\s*}}`, "g");
      content = content.replace(regex, value);
    }

    return content;
  }

  async sendVerificationEmail(user, token) {
    const verifyPath = this.config.routes?.verify || '/verify';
    const url = `${this.joinUrl(this.baseUrl, verifyPath)}?token=${token}`;

    const html = this.loadTemplate("email-verification", {
      name: user.name || user.email,
      url
    }) || `Click to verify your email: <a href="${url}">${url}</a>`;

    return this.send({
      to: user.email,
      subject: "Verify Your Email",
      html,
      text: `Verify your email: ${url}`
    });
  }

  async sendPasswordResetEmail(user, token) {
    const resetPath = this.config.routes?.resetPassword || '/reset-password';
    const url = `${this.joinUrl(this.baseUrl, resetPath)}?token=${token}`;

    const html = this.loadTemplate("password-reset", {
      name: user.name || user.email,
      url
    }) || `Reset password: <a href="${url}">${url}</a>`;

    return this.send({
      to: user.email,
      subject: "Reset Your Password",
      html,
      text: `Reset your password: ${url}`
    });
  }

  async sendLoginAlert(user, info) {
    info = info || {};
    const ip = info.ip || 'unknown';
    const userAgent = info.userAgent || 'unknown';

    const html = this.loadTemplate("login-alert", {
      name: user.name || user.email,
      ip,
      agent: userAgent
    }) || `
      New login detected.<br>
      IP: ${ip}<br>
      User Agent: ${userAgent}
    `;

    return this.send({
      to: user.email,
      subject: "New Login Detected",
      html,
      text: `New login from IP ${ip}`
    });
  }

  async send2FACode(user, code) {
    const html = this.loadTemplate("twofa-code", {
      name: user.name || user.email,
      code
    }) || `Your 2FA code: <b>${code}</b>`;

    return this.send({
      to: user.email,
      subject: "Your 2FA Code",
      html,
      text: `Your 2FA code is: ${code}`
    });
  }

  async sendMagicLink(user, url) {
    const html = this.loadTemplate("magic-link", {
      name: user.name || user.email,
      url
    }) || `Sign in with this magic link: <a href="${url}">${url}</a><br>This link expires in 15 minutes.`;

    return this.send({
      to: user.email,
      subject: "Your Magic Sign-In Link",
      html,
      text: `Sign in here: ${url} (expires in 15 minutes)`
    });
  }

  async sendMagicLink(user, url) {
    const html = this.loadTemplate("magic-link", {
      name: user.name || user.email,
      url
    }) || `Sign in with this magic link: <a href="${url}">${url}</a><br>This link expires in 15 minutes.`;

    return this.send({
      to: user.email,
      subject: "Your Magic Sign-In Link",
      html,
      text: `Sign in here: ${url} (expires in 15 minutes)`
    });
  }

  async sendAccountLockEmail(user) {
    const html = this.loadTemplate("account-locked", {
      name: user.name || user.email
    }) || `
      Your account has been locked due to too many failed login attempts.<br>
      Try again after 1 hour.
    `;

    return this.send({
      to: user.email,
      subject: "Your Account Has Been Locked",
      html,
      text: "Your account is locked for 1 hour due to failed login attempts."
    });
  }
}

module.exports = EmailService;
