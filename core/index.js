'use strict';

const path = require('path');
const { loadConfig } = require('./configLoader');
const { AuthManager } = require('./auth/authManager');
const { KatanaRunner } = require('./crawler/katanaRunner');
const { SwaggerDiscovery } = require('./crawler/swaggerDiscovery');
const { mergeEndpoints } = require('./crawler/endpointMerger');
const { ZapRunner } = require('./zap/zapRunner');
const { NucleiRunner } = require('./nuclei/nucleiRunner');
const { normalizeAll } = require('./normalizer/normalizer');
const { generateReports } = require('./reporter');
const { makeRunOutputDir } = require('./utils/fsHelpers');
const { Logger } = require('./utils/logger');

const TOTAL_STEPS = 8;

/**
 * Runs the full scan pipeline end to end:
 *   auth -> katana -> swagger -> merge -> zap -> nuclei -> normalize -> report
 *
 * @param {string|object} configInput - a target URL, a path to a config JSON file, or a config object
 * @param {object} [overrides] - CLI flag overrides layered on top
 * @returns {Promise<{reportPaths: object, normalizedResult: object, runOutputDir: string}>}
 */
async function runScan(configInput, overrides = {}) {
  const config = loadConfig(configInput, overrides);
  const log = new Logger('pipeline', config.logLevel);
  const startedAt = new Date().toISOString();

  const runOutputDir = makeRunOutputDir(config.reporting.outputDir, config.target);
  log.info(`Scan output directory: ${runOutputDir}`);

  // Step 1: Authentication
  log.step(1, TOTAL_STEPS, 'Preparing authentication');
  const authManager = new AuthManager(config.authentication);
  await authManager.prepare();

  // Step 2: Katana crawl
  log.step(2, TOTAL_STEPS, 'Crawling with Katana');
  const katana = new KatanaRunner(config, authManager, runOutputDir);
  const katanaResult = await katana.run(config.target);

  // Step 3: Swagger/OpenAPI discovery
  log.step(3, TOTAL_STEPS, 'Discovering Swagger/OpenAPI specs');
  const swagger = new SwaggerDiscovery(config, authManager, runOutputDir);
  const swaggerResult = await swagger.probe(config.target);

  // Step 4: Merge + normalize endpoints
  log.step(4, TOTAL_STEPS, 'Merging discovered endpoints');
  const { endpoints, txtPath: endpointsFile } = mergeEndpoints(
    { katanaUrls: katanaResult.urls, swaggerEndpoints: swaggerResult.endpoints, target: config.target },
    runOutputDir
  );

  // Step 5: OWASP ZAP
  log.step(5, TOTAL_STEPS, 'Running OWASP ZAP (passive + active scan)');
  const zap = new ZapRunner(config, authManager, runOutputDir);
  const zapResult = await zap.run(config.target, endpointsFile);

  // Step 6: Nuclei
  log.step(6, TOTAL_STEPS, 'Running Nuclei template scan');
  const nuclei = new NucleiRunner(config, authManager, runOutputDir);
  const nucleiResult = await nuclei.run(endpointsFile, config.target);

  // Step 7: Normalize
  log.step(7, TOTAL_STEPS, 'Normalizing results into common schema');
  const finishedAt = new Date().toISOString();
  const normalizedResult = normalizeAll({
    zapReportPath: zapResult.reportPath,
    nucleiFindings: nucleiResult.findings,
    katanaUrls: endpoints,
    target: config.target,
    startedAt,
    finishedAt
  });

  // Step 8: Reports
  log.step(8, TOTAL_STEPS, 'Generating HTML / JSON / SARIF reports');
  const reportingConfig = { ...config.reporting, outputDir: runOutputDir };
  const reportPaths = generateReports(normalizedResult, reportingConfig);

  log.success(`Scan complete: ${normalizedResult.summary.total} findings (critical=${normalizedResult.summary.critical}, high=${normalizedResult.summary.high})`);

  return {
    reportPaths,
    normalizedResult,
    runOutputDir,
    skippedSteps: {
      katana: katanaResult.skipped,
      zap: zapResult.skipped,
      nuclei: nucleiResult.skipped
    }
  };
}

/** Determine process exit code based on the configured failure threshold. */
function computeExitCode(normalizedResult, failOn) {
  if (!failOn || failOn === 'none') return 0;
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  const thresholdIndex = order.indexOf(failOn);
  if (thresholdIndex === -1) return 0;

  for (let i = thresholdIndex; i < order.length; i++) {
    if (normalizedResult.summary[order[i]] > 0) return 1;
  }
  return 0;
}

module.exports = { runScan, computeExitCode };
