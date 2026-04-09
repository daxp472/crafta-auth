// packages/auth/src/utils/email.js
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

class EmailService {
  constructor(config) {
    this.config = config;
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

  // Reusable sender
  async send({ to, subject, html, text }) {
    if (!this.smtpEnabled) {
      return { sent: false, reason: 'smtp_disabled' };
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

    // Replace {{variable}}
    for (const key of Object.keys(variables)) {
      content = content.replace(new RegExp(`{{${key}}}`, "g"), variables[key]);
    }

    return content;
  }

  async sendVerificationEmail(user, token) {
    const verifyPath = this.config.routes?.verify || '/verify';
    const url = `${this.config.baseUrl}${verifyPath}?token=${token}`;

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
    const url = `${this.config.baseUrl}${resetPath}?token=${token}`;

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
    const html = this.loadTemplate("login-alert", {
      name: user.name || user.email,
      ip: info.ip,
      agent: info.userAgent
    }) || `
      New login detected.<br>
      IP: ${info.ip}<br>
      User Agent: ${info.userAgent}
    `;

    return this.send({
      to: user.email,
      subject: "New Login Detected",
      html,
      text: `New login from IP ${info.ip}`
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
