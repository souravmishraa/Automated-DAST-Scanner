'use strict';

const { Logger } = require('../utils/logger');
const { withRetry } = require('../utils/exec');
const { extractLoginForm, buildLoginBody } = require('../utils/htmlForm');

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

    if (this.type === 'oauth' && !this.config.token && !this.config.loginUrl) {
      throw new Error('OAuth authentication requires either a pre-fetched "token" or a "loginUrl" token endpoint.');
    }
    if (this.type === 'jsonLogin') {
      await this.performJsonLogin();
    }
    if (this.type === 'form') {
      await this.performFormLogin();
    }
  }

  /**
   * Performs a real login POST against a JSON-API login endpoint (the pattern most
   * SPA/JS frontends use, as opposed to a classic HTML <form> POST). Unlike a manually
   * pre-fetched bearer token, this also records the exact login request body (with real
   * field names) via `getSeedRequests()`, so ZAP's active scanner can fuzz the actual
   * email/password fields directly - the same thing a human gets "for free" by logging
   * in through Burp/ZAP's proxy before running an automated scan.
   */
  async performJsonLogin() {
    const { loginUrl, usernameField = 'username', passwordField = 'password', username, password, tokenPath = 'token' } = this.config;
    if (!loginUrl || !username || !password) {
      throw new Error('jsonLogin authentication requires "loginUrl", "username", and "password".');
    }

    const bodyObj = { [usernameField]: username, [passwordField]: password };
    const bodyText = JSON.stringify(bodyObj);

    // A single transient blip (e.g. a 502/503 from a target waking up from idle, or a brief
    // network hiccup) shouldn't abort the entire scan at step 1 - retry those, but don't
    // retry a definitive auth rejection (401/403), since wrong credentials will never succeed.
    const res = await withRetry(
      async () => {
        const response = await fetch(loginUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: bodyText
        });
        if (!response.ok) {
          const err = new Error(`jsonLogin failed: POST ${loginUrl} returned ${response.status}`);
          err.status = response.status;
          throw err;
        }
        return response;
      },
      {
        retries: 3,
        baseDelayMs: 2000,
        label: 'jsonLogin',
        shouldRetry: (err) => !(err.status && err.status >= 400 && err.status < 500)
      }
    );
    const data = await res.json();
    const token = tokenPath.split('.').reduce((obj, key) => (obj == null ? undefined : obj[key]), data);
    if (!token) {
      throw new Error(`jsonLogin: could not find a token at response path "${tokenPath}"`);
    }

    this.token = token;
    this.loginSeedRequest = { url: loginUrl, method: 'POST', body: bodyText, contentType: 'application/json' };
    log.success(`jsonLogin succeeded against ${loginUrl}; extracted token via "${tokenPath}".`);
  }

  /**
   * Performs a real login POST against a classic HTML <form> (session-cookie) login
   * endpoint, and captures the resulting session cookie for reuse as a static header on
   * every subsequent request - the same "static header, no per-request re-auth" pattern
   * used for jsonLogin/bearer. Deliberately does NOT hand this off to ZAP's own
   * context/session-management ("user"-attached spider/activeScan) flow: that path was
   * empirically found to be unreliable in this environment (ZAP's internal HSQLDB
   * connection repeatedly closing mid-activeScan whenever a context user was attached,
   * 100% reproducible across many runs, 0% reproducible without one) - a static cookie
   * sidesteps ZAP's per-request re-authentication/verification machinery entirely,
   * matching the reliable behavior already proven for jsonLogin/bearer auth.
   *
   * The login page's actual <form> markup is fetched and parsed (see utils/htmlForm.js) so
   * a user only ever has to supply loginUrl/username/password - hidden anti-CSRF tokens,
   * submit-button fields, and field names are discovered automatically, not hand-configured.
   *
   * Most PHP-session apps keep the SAME session id across the login transition
   * (session_start() before login just flips an "authenticated" flag server-side) - so we
   * grab the cookie from the initial GET and reuse it verbatim after POSTing credentials
   * with it attached, rather than trying to parse a possibly-rotated cookie out of the
   * login response.
   */
  async performFormLogin() {
    const { loginUrl, username, password, usernameField, passwordField } = this.config;
    if (!loginUrl || !username || !password) {
      throw new Error('form authentication requires "loginUrl", "username", and "password".');
    }

    const getSetCookiePairs = (res) => {
      const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get('set-cookie')].filter(Boolean);
      return raw.map((c) => c.split(';')[0].trim()).filter(Boolean);
    };

    const pageRes = await fetch(loginUrl, { redirect: 'manual' });
    const cookieMap = new Map(getSetCookiePairs(pageRes).map((pair) => pair.split('=').map((s) => s.trim())));
    const html = await pageRes.text();
    const form = extractLoginForm(html);
    if (!form) {
      throw new Error(`form authentication: could not find a <form> with a password field on ${loginUrl}`);
    }
    const bodyParams = buildLoginBody(form, { username, password, usernameField, passwordField });
    const cookieHeader = () => Array.from(cookieMap.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
    const postUrl = form.action ? new URL(form.action, loginUrl).toString() : loginUrl;

    // A single transient blip shouldn't abort the entire scan at step 1 - retry those, but
    // don't retry a definitive auth rejection (4xx), since wrong credentials never succeed.
    const res = await withRetry(
      async () => {
        const response = await fetch(postUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            ...(cookieHeader() ? { Cookie: cookieHeader() } : {})
          },
          body: bodyParams.toString(),
          redirect: 'manual'
        });
        if (response.status >= 400 && response.status < 500) {
          const err = new Error(`form login failed: POST ${postUrl} returned ${response.status}`);
          err.status = response.status;
          throw err;
        }
        // A redirect back to the login page itself (wrong credentials, or a stale
        // anti-CSRF token) is a silent failure - fetch won't surface it as an HTTP error
        // status, but scanning with an unauthenticated cookie produces a scan that
        // "succeeds" while silently finding nothing behind the login wall.
        const location = response.headers.get('location') || '';
        if (response.status >= 300 && response.status < 400 && /log[-_]?in/i.test(location)) {
          const err = new Error(`form login failed: POST ${postUrl} redirected back to "${location}" - check the username/password are correct`);
          throw err;
        }
        return response;
      },
      {
        retries: 3,
        baseDelayMs: 2000,
        label: 'form login',
        shouldRetry: (err) => !(err.status && err.status >= 400 && err.status < 500)
      }
    );

    // Merge in any cookies the login POST itself rotated/added, over the pre-login ones.
    getSetCookiePairs(res).forEach((pair) => {
      const [k, v] = pair.split('=').map((s) => s.trim());
      cookieMap.set(k, v);
    });
    this.cookieHeader = cookieHeader();
    if (!this.cookieHeader) {
      throw new Error('form authentication: no session cookie was captured from the login flow.');
    }

    this.loginSeedRequest = {
      url: postUrl,
      method: 'POST',
      body: bodyParams.toString(),
      contentType: 'application/x-www-form-urlencoded'
    };
    log.success(`form login succeeded against ${postUrl}; captured session cookie.`);
  }

  /**
   * Extra real, field-populated requests (the login POST, when using jsonLogin/form) that
   * should be seeded directly into ZAP's Sites tree, since discovery crawling can only ever
   * see the login URL as a bare string, never the real POST body.
   */
  getSeedRequests() {
    return this.loginSeedRequest ? [this.loginSeedRequest] : [];
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
      case 'jsonLogin':
        return this.token ? [`Authorization: Bearer ${this.token}`] : [];
      case 'apiKey':
        return [`${this.config.apiKeyHeader || 'X-API-Key'}: ${this.config.apiKeyValue}`];
      case 'cookie':
        return [`Cookie: ${this.config.cookie}`];
      case 'form':
        return this.cookieHeader ? [`Cookie: ${this.cookieHeader}`] : [];
      default:
        return [];
    }
  }

  /** True if this auth type is a static header injected on every request. */
  isHeaderBased() {
    return ['basic', 'bearer', 'apiKey', 'cookie', 'oauth', 'jsonLogin', 'form'].includes(this.type);
  }
}

module.exports = { AuthManager };
