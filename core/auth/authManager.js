'use strict';

const { Logger } = require('../utils/logger');

const log = new Logger('auth');

/**
 * AuthManager builds the artifacts every downstream tool needs from a single
 * authentication config block: HTTP headers for Katana/Nuclei, and a ZAP
 * Automation Framework "authentication" + "user" plan fragment.
 *
 * The user never hands Katana/ZAP/Nuclei their own auth config - this module
 * is the single translation layer.
 */
class AuthManager {
  constructor(authConfig = { type: 'none' }) {
    this.config = authConfig;
    this.type = authConfig.type || 'none';
  }

  /** Perform any live steps needed (e.g. verifying a login form responds). */
  async prepare() {
    if (this.type === 'none') {
      log.info('No authentication configured; scanning as an anonymous user.');
      return;
    }
    log.info(`Preparing authentication of type "${this.type}"`);

    if (this.type === 'form' && !this.config.loginUrl) {
      throw new Error('Form authentication requires "loginUrl".');
    }
    if (this.type === 'oauth' && !this.config.token && !this.config.loginUrl) {
      throw new Error('OAuth authentication requires either a pre-fetched "token" or a "loginUrl" token endpoint.');
    }
  }

  /**
   * Plain HTTP headers usable directly by Katana (-H) and Nuclei (-H).
   * @returns {string[]} array of "Header: value" strings
   */
  getHttpHeaders() {
    switch (this.type) {
      case 'basic': {
        const encoded = Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64');
        return [`Authorization: Basic ${encoded}`];
      }
      case 'bearer':
      case 'oauth':
        return [`Authorization: Bearer ${this.config.token}`];
      case 'apiKey':
        return [`${this.config.apiKeyHeader || 'X-API-Key'}: ${this.config.apiKeyValue}`];
      case 'cookie':
        return [`Cookie: ${this.config.cookie}`];
      case 'form':
        // Form auth is session-driven; cookie is injected after login (see loginAndGetCookie).
        return [];
      default:
        return [];
    }
  }

  /**
   * Generates the ZAP Automation Framework "env.contexts[].authentication"
   * and "users" fragments for this auth type.
   */
  toZapAuthPlan(target) {
    const contextName = 'security-framework-context';

    if (this.type === 'form') {
      return {
        authentication: {
          method: 'form',
          parameters: {
            loginPageUrl: this.config.loginUrl,
            loginRequestUrl: this.config.loginUrl,
            loginRequestBody: `${this.config.usernameField || 'username'}={%username%}&${
              this.config.passwordField || 'password'
            }={%password%}`
          },
          verification: {
            method: this.config.loggedInIndicator ? 'response' : 'poll',
            loggedInRegex: this.config.loggedInIndicator || undefined,
            loggedOutRegex: this.config.loggedOutIndicator || undefined
          }
        },
        users: [
          {
            name: 'scanner-user',
            credentials: {
              username: this.config.username,
              password: this.config.password
            }
          }
        ]
      };
    }

    if (['basic', 'bearer', 'apiKey', 'cookie', 'oauth'].includes(this.type)) {
      // These are stateless header-based auths -> ZAP "httpsender" script or
      // replacer rule injecting a static header on every request.
      return {
        authentication: {
          method: 'manual',
          headers: this.getHttpHeaders()
        },
        users: []
      };
    }

    return { authentication: null, users: [] };
  }

  /** True if this auth type is a static header injected on every request. */
  isHeaderBased() {
    return ['basic', 'bearer', 'apiKey', 'cookie', 'oauth'].includes(this.type);
  }

  /** True if this auth type requires ZAP's stateful form-login flow. */
  isSessionBased() {
    return this.type === 'form';
  }
}

module.exports = { AuthManager };
