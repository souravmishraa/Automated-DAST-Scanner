'use strict';

const path = require('path');
const { writeJson } = require('../utils/fsHelpers');
const { Logger } = require('../utils/logger');

const log = new Logger('swagger-discovery');

/**
 * Probes common Swagger/OpenAPI spec locations and, if found, parses the
 * spec into a flat list of endpoints so they can be merged with the
 * Katana-discovered URLs (hidden API routes are often missed by crawling).
 */
class SwaggerDiscovery {
  constructor(config, authManager, runOutputDir) {
    this.config = config.apiDiscovery;
    this.authManager = authManager;
    this.runOutputDir = runOutputDir;
  }

  buildHeaders() {
    const headers = { Accept: 'application/json, */*' };
    for (const h of this.authManager.getHttpHeaders()) {
      const idx = h.indexOf(':');
      headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
    }
    return headers;
  }

  async probe(target) {
    if (!this.config.enabled) {
      log.info('API discovery disabled in config; skipping.');
      return { specUrl: null, endpoints: [] };
    }

    const base = target.replace(/\/$/, '');
    const headers = this.buildHeaders();

    for (const p of this.config.paths) {
      const candidate = `${base}${p}`;
      try {
        const res = await fetch(candidate, { headers, redirect: 'follow' });
        if (res.ok) {
          const contentType = res.headers.get('content-type') || '';
          if (contentType.includes('json') || p.endsWith('.json')) {
            const spec = await res.json();
            if (spec && (spec.paths || spec.swagger || spec.openapi)) {
              log.success(`Found API spec at ${candidate}`);
              return this.parseSpec(candidate, spec);
            }
          }
        }
      } catch (err) {
        // 404 / network error - just move to next candidate path
        log.debug(`No spec at ${candidate} (${err.message})`);
      }
    }

    log.info('No Swagger/OpenAPI spec discovered.');
    return { specUrl: null, endpoints: [] };
  }

  parseSpec(specUrl, spec) {
    const endpoints = [];
    const base = this.deriveBaseUrl(specUrl, spec);

    const paths = spec.paths || {};
    for (const [routePath, methods] of Object.entries(paths)) {
      for (const method of Object.keys(methods)) {
        if (!['get', 'post', 'put', 'delete', 'patch', 'options', 'head'].includes(method)) continue;
        endpoints.push({
          url: `${base}${routePath}`,
          method: method.toUpperCase(),
          source: 'swagger',
          operationId: methods[method].operationId || null
        });
      }
    }

    writeJson(path.join(this.runOutputDir, 'swagger-endpoints.json'), { specUrl, endpoints });
    log.success(`Extracted ${endpoints.length} endpoints from API spec`);
    return { specUrl, endpoints };
  }

  deriveBaseUrl(specUrl, spec) {
    try {
      const specUrlObj = new URL(specUrl);
      if (spec.servers && spec.servers.length) {
        // OpenAPI 3.x
        const server = spec.servers[0].url;
        return server.startsWith('http') ? server.replace(/\/$/, '') : `${specUrlObj.origin}${server}`.replace(/\/$/, '');
      }
      if (spec.host) {
        // Swagger 2.0
        const scheme = (spec.schemes && spec.schemes[0]) || specUrlObj.protocol.replace(':', '');
        const basePath = spec.basePath || '';
        return `${scheme}://${spec.host}${basePath}`.replace(/\/$/, '');
      }
      return specUrlObj.origin;
    } catch (err) {
      return '';
    }
  }
}

module.exports = { SwaggerDiscovery };
