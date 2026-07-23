'use strict';

const path = require('path');
const { writeJson, writeText } = require('../utils/fsHelpers');
const { Logger } = require('../utils/logger');

const log = new Logger('endpoint-merger');

/** Normalize a URL for dedup purposes: strip trailing slash, sort query params, lowercase host. */
function normalizeUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    u.hash = '';
    const params = [...u.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
    u.search = '';
    for (const [k, v] of params) u.searchParams.append(k, v);
    let normalized = `${u.protocol}//${u.host.toLowerCase()}${u.pathname.replace(/\/+$/, '') || '/'}`;
    if ([...u.searchParams].length) normalized += `?${u.searchParams.toString()}`;
    return normalized;
  } catch (err) {
    return rawUrl;
  }
}

/**
 * Merges Katana-discovered URLs with Swagger/OpenAPI-discovered endpoints,
 * de-duplicates, and writes master-endpoints.json / master-endpoints.txt.
 *
 * Scoped to the target's own hostname: crawlers (especially Katana's JS-crawl mode)
 * routinely follow third-party URLs referenced in scripts/CDNs/analytics - those must
 * never reach ZAP's active scan or Nuclei, since the user only authorized `target`.
 */
function mergeEndpoints({ katanaUrls = [], swaggerEndpoints = [], target = null }, runOutputDir) {
  const targetHost = target ? new URL(target).hostname.toLowerCase() : null;
  const inScope = (rawUrl) => {
    if (!targetHost) return true;
    try {
      return new URL(rawUrl).hostname.toLowerCase() === targetHost;
    } catch (err) {
      return false;
    }
  };

  const scopedKatanaUrls = katanaUrls.filter((e) => inScope(e.url));
  const scopedSwaggerEndpoints = swaggerEndpoints.filter((e) => inScope(e.url));
  const outOfScopeCount = (katanaUrls.length - scopedKatanaUrls.length) + (swaggerEndpoints.length - scopedSwaggerEndpoints.length);

  const seen = new Map();

  for (const entry of scopedKatanaUrls) {
    const key = normalizeUrl(entry.url);
    if (!seen.has(key)) {
      seen.set(key, { url: entry.url, normalizedUrl: key, method: entry.method || 'GET', sources: ['katana'] });
    } else {
      seen.get(key).sources.push('katana');
    }
  }

  for (const entry of scopedSwaggerEndpoints) {
    const key = normalizeUrl(entry.url);
    if (!seen.has(key)) {
      seen.set(key, {
        url: entry.url,
        normalizedUrl: key,
        method: entry.method || 'GET',
        sources: ['swagger'],
        operationId: entry.operationId || null
      });
    } else {
      const existing = seen.get(key);
      if (!existing.sources.includes('swagger')) existing.sources.push('swagger');
    }
  }

  const merged = [...seen.values()];
  log.success(
    `Merged endpoints: ${scopedKatanaUrls.length} from Katana + ${scopedSwaggerEndpoints.length} from Swagger -> ${merged.length} unique`
  );
  if (outOfScopeCount > 0) {
    log.warn(`Dropped ${outOfScopeCount} out-of-scope URL(s) (different host than target "${targetHost}") before scanning.`);
  }

  const jsonPath = path.join(runOutputDir, 'master-endpoints.json');
  const txtPath = path.join(runOutputDir, 'master-endpoints.txt');
  writeJson(jsonPath, merged);
  writeText(txtPath, merged.map((e) => e.url).join('\n'));

  return { endpoints: merged, jsonPath, txtPath };
}

module.exports = { mergeEndpoints, normalizeUrl };
