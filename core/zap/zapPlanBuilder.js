'use strict';

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1']);

/**
 * ZAP runs inside its own Docker container, where "localhost"/"127.0.0.1" refers to the
 * container itself, not the host machine - so a target actually running on the same host
 * (a very common case: testing a locally-running app before it's deployed) is unreachable
 * from inside the container unless rewritten to "host.docker.internal" (the Docker-provided
 * hostname that routes back to the host; made to work universally via the --add-host flag
 * in zapRunner.js's runDocker(), since it isn't automatic outside Docker Desktop). Katana/
 * Nuclei run natively on the host, so they must keep using the original hostname - this
 * rewrite is applied only to what feeds into the ZAP plan, nowhere else in the pipeline.
 */
function rewriteForDocker(url, mode) {
  if (mode !== 'docker' || !url) return url;
  try {
    const u = new URL(url);
    if (LOCAL_HOSTNAMES.has(u.hostname)) {
      u.hostname = 'host.docker.internal';
      return u.toString();
    }
    return url;
  } catch (err) {
    return url;
  }
}

/**
 * Builds an OWASP ZAP Automation Framework YAML plan (as a plain JS object,
 * later serialized with js-yaml) purely from the framework's own config +
 * the merged endpoint list. The end user never sees or edits this file.
 *
 * Reference: https://www.zaproxy.org/docs/automate/automation-framework/
 */
function buildZapPlan({ target, config, authManager, endpoints = [], runOutputDir }) {
  const contextName = config.zap.contextName || 'security-framework-context';
  const jobs = [];
  target = rewriteForDocker(target, config.zap.mode);

  // 1. env: define context, scope, and (if applicable) auth + users
  const contextDef = {
    name: contextName,
    urls: [target],
    includePaths: [`${target}.*`]
  };

  // Note: `env` (contexts/users) is a top-level Automation Framework key, not a job - it's
  // attached to the returned plan object below, not pushed into `jobs`. There's no
  // session-based (ZAP context/user) auth path here anymore - form auth used to hand off to
  // ZAP's own per-request re-authentication flow, but that was empirically found to be
  // unreliable (ZAP's internal HSQLDB connection repeatedly closing mid-activeScan whenever
  // a context user was attached, 100% reproducible against DVWA). All auth types now flow
  // through the header-based path below (see authManager.performFormLogin()), the same
  // reliable static-header pattern already proven for jsonLogin/bearer.

  // 2. Header-based auth (basic/bearer/apiKey/cookie/oauth/jsonLogin/form) -> replacer job
  //    injects a static header on every request ZAP makes.
  if (authManager.isHeaderBased()) {
    const headers = authManager.getHttpHeaders();
    if (headers.length) {
      const rules = headers.map((h, idx) => {
        const sepIdx = h.indexOf(':');
        return {
          description: `security-framework-auth-header-${idx}`,
          url: '',
          matchType: 'REQ_HEADER',
          matchString: h.slice(0, sepIdx).trim(),
          replacementString: h.slice(sepIdx + 1).trim(),
          initiators: []
        };
      });
      jobs.push({
        type: 'replacer',
        parameters: { deleteAllRules: false },
        rules
      });
    }
  }

  // 3b. Requestor: seed ZAP's Sites tree with every endpoint Katana/Swagger discovered.
  // ZAP's own built-in spider (job below) is far shallower than Katana's JS-aware crawl -
  // without this, active scan only ever tests the handful of URLs ZAP's spider finds
  // itself, missing most of the parameterized endpoints (login, search, etc.) that matter
  // most for injection testing (SQLi, XSS, ...).
  const seedRequests = endpoints.map((endpoint, idx) => {
    const method = (endpoint.method || 'GET').toUpperCase();
    const request = { url: rewriteForDocker(endpoint.url, config.zap.mode), method, name: `seed-${idx}` };
    if (method !== 'GET' && method !== 'HEAD') {
      // No request-body schema is known for a crawled (non-Swagger) endpoint - send a
      // minimal JSON body so ZAP's active scanner has a parameter to fuzz on POST/PUT/
      // PATCH endpoints, instead of skipping them entirely for lack of any body at all.
      request.data = endpoint.sampleBody || '{}';
      request.headers = [`Content-Type: ${endpoint.contentType || 'application/json'}`];
    }
    return request;
  });

  // authManager.getSeedRequests() (e.g. jsonLogin's real login POST, with real field names
  // like email/password) is far more valuable than a crawled guess for the same URL - a
  // human logging in through Burp/ZAP's proxy gets this "for free"; we have to build it
  // explicitly since nothing here observes real form submissions. Let it override any
  // crawled entry for the same URL rather than just appending a duplicate.
  const authSeedRequests = authManager.getSeedRequests().map((req, idx) => ({
    url: rewriteForDocker(req.url, config.zap.mode),
    method: req.method,
    name: `auth-seed-${idx}`,
    data: req.body,
    headers: [`Content-Type: ${req.contentType || 'application/json'}`]
  }));
  const overriddenUrls = new Set(authSeedRequests.map((r) => r.url));
  const allRequests = [...seedRequests.filter((r) => !overriddenUrls.has(r.url)), ...authSeedRequests];

  if (allRequests.length) {
    jobs.push({
      type: 'requestor',
      parameters: {},
      requests: allRequests
    });
  }

  // 4. Passive scan config
  jobs.push({
    type: 'passiveScan-config',
    parameters: {
      maxAlertsPerRule: 10,
      scanOnlyInScope: true
    }
  });

  // 5. Spider (traditional)
  jobs.push({
    type: 'spider',
    parameters: {
      context: contextName,
      url: target,
      maxDuration: config.zap.spiderMaxDurationMinutes || 10
    }
  });

  // 6. Ajax spider (only if explicitly requested - it's heavyweight)
  if (config.zap.ajaxSpider) {
    jobs.push({
      type: 'spiderAjax',
      parameters: {
        context: contextName,
        url: target,
        maxDuration: config.zap.spiderMaxDurationMinutes || 10
      }
    });
  }

  // 7. Ensure passive scan completes
  jobs.push({ type: 'passiveScan-wait', parameters: { maxDuration: 5 } });

  // 8. Active scan
  if (config.zap.activeScan) {
    const activeScanJob = {
      type: 'activeScan',
      parameters: {
        context: contextName,
        maxScanDurationInMins: config.zap.activeScanMaxDurationMinutes || 30,
        maxRuleDurationInMins: 5,
        // Default is 2x CPU cores (8 on a 4-core box) - empirically reproduced this flooding
        // ZAP's internal HSQLDB with concurrent reads/writes on constrained Docker/WSL2 hosts,
        // causing "SQLNonTransientConnectionException: connection exception: closed" en masse
        // and every scan rule silently completing with 0 messages sent / 0 alerts raised.
        // Lower and override via config.zap.activeScanThreadsPerHost if the host can take more.
        threadPerHost: config.zap.activeScanThreadsPerHost || 2
      }
    };

    // Explicit scan policy: keeps broad/low-value checks at conservative defaults, but
    // pushes the categories that matter most (SQLi, XSS, XXE, Path Traversal, Command
    // Injection) to high strength / low threshold, instead of silently running everything
    // at ZAP's implicit Default Policy (medium/medium across the board). Rule IDs are real
    // ascanrules plugin IDs sourced from zaproxy/zaproxy's own docs/scanners.md, not guessed -
    // env.parameters.failOnError is false below, so a wrong ID would otherwise silently no-op.
    // SSRF (rule 40046) is deliberately NOT included: it lives in ZAP's Beta scan-rules
    // add-on (not present in the zaproxy/zap-stable image, hence the "Unrecognised active
    // scan rule ID" warning when it was included), and even installed it only detects blind
    // SSRF via out-of-band callbacks, which requires OAST infrastructure this framework
    // doesn't run - a known, accepted limitation, not a bug.
    const policy = config.zap.activeScanPolicy;
    if (policy) {
      activeScanJob.policyDefinition = {
        defaultStrength: policy.defaultStrength || 'medium',
        defaultThreshold: policy.defaultThreshold || 'medium',
        rules: (policy.focusRules || []).map((r) => ({
          id: r.id,
          name: r.name,
          strength: r.strength || 'high',
          threshold: r.threshold || 'low'
        }))
      };
    }

    jobs.push(activeScanJob);
  }

  // 9. Reports - JSON + HTML (ZAP's native ones, used only as raw input to
  //    our own normalizer/reporter, never shown directly to the user)
  jobs.push({
    type: 'report',
    parameters: {
      template: 'traditional-json',
      reportDir: runOutputDir,
      reportFile: 'zap-report.json',
      reportTitle: 'Security Framework - ZAP Raw Findings',
      reportDescription: 'Raw ZAP output, consumed by the result normalizer.'
    }
  });

  jobs.push({
    type: 'report',
    parameters: {
      template: 'sarif-json',
      reportDir: runOutputDir,
      reportFile: 'zap-report.sarif.json',
      reportTitle: 'Security Framework - ZAP SARIF'
    }
  });

  return {
    env: {
      contexts: [contextDef],
      // failOnError: false — prevents unrecognised job types/params from aborting the whole scan.
      parameters: { failOnError: false, failOnWarning: false, progressToStdout: true }
    },
    jobs
  };
}

module.exports = { buildZapPlan };
