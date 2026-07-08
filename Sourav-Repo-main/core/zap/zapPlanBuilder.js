'use strict';

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

  // 1. env: define context, scope, and (if applicable) auth + users
  const contextDef = {
    name: contextName,
    urls: [target],
    includePaths: [`${target}.*`]
  };

  if (authManager.isSessionBased()) {
    const plan = authManager.toZapAuthPlan(target);
    contextDef.authentication = {
      method: 'form',
      parameters: plan.authentication.parameters,
      verification: plan.authentication.verification
    };
    contextDef.users = plan.users.map((u) => ({
      name: u.name,
      credentials: { username: u.credentials.username, password: u.credentials.password }
    }));
  }

  // Note: `env` (contexts/users) is a top-level Automation Framework key,
  // not a job - it's attached to the returned plan object below, not pushed
  // into `jobs`.

  // 2. Header-based auth (basic/bearer/apiKey/cookie/oauth) -> replacer job
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
  if (endpoints.length) {
    jobs.push({
      type: 'requestor',
      parameters: {},
      requests: endpoints.map((url, idx) => ({ url, method: 'GET', name: `seed-${idx}` }))
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
      user: authManager.isSessionBased() ? 'scanner-user' : undefined,
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
    jobs.push({
      type: 'activeScan',
      parameters: {
        context: contextName,
        user: authManager.isSessionBased() ? 'scanner-user' : undefined,
        maxScanDurationInMins: config.zap.activeScanMaxDurationMinutes || 30,
        maxRuleDurationInMins: 5
      }
    });
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
