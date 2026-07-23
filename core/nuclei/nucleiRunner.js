'use strict';

const path = require('path');
const { run, checkBinaryAvailable, withRetry } = require('../utils/exec');
const { exists, readJson, writeJson } = require('../utils/fsHelpers');
const fs = require('fs');
const { Logger } = require('../utils/logger');

const log = new Logger('nuclei');

/**
 * Runs Nuclei against the merged master-endpoints list using the official
 * template repository. Requires the `nuclei` binary on PATH
 * (https://github.com/projectdiscovery/nuclei).
 */
class NucleiRunner {
  constructor(config, authManager, runOutputDir) {
    this.config = config.nuclei;
    this.authManager = authManager;
    this.runOutputDir = runOutputDir;
  }

  async isAvailable() {
    return checkBinaryAvailable('nuclei', '-version');
  }

  buildArgs(endpointsFile) {
    const jsonOut = path.join(this.runOutputDir, 'nuclei-report.jsonl');
    const sarifOut = path.join(this.runOutputDir, 'nuclei-report.sarif.json');

    const args = [
      '-l', endpointsFile,
      '-jsonl', '-jsonl-export', jsonOut,
      '-sarif-export', sarifOut,
      '-severity', this.config.severities.join(','),
      '-rl', String(this.config.rateLimit || 150),
      '-c', String(this.config.concurrency || 25),
      '-silent',
      '-no-color'
    ];

    if (this.config.templates && this.config.templates.length) {
      for (const tag of this.config.templates) {
        args.push('-tags', tag);
      }
    }

    for (const header of this.authManager.getHttpHeaders()) {
      args.push('-H', header);
    }

    return { args, jsonOut, sarifOut };
  }

  async run(endpointsFile, fallbackTarget = null) {
    const available = await this.isAvailable();
    if (!available) {
      log.warn('Nuclei binary not found on PATH. Skipping Nuclei scan (results will be incomplete).');
      log.warn('Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest');
      return { findings: [], jsonOut: null, sarifOut: null, skipped: true };
    }

    // Keep templates fresh; ignore failures (offline environments etc.)
    try {
      await run('nuclei', ['-update-templates', '-silent'], { timeoutMs: 120000, silent: true });
    } catch (err) {
      log.debug(`Template update skipped: ${err.message}`);
    }

    const { args, jsonOut, sarifOut } = this.buildArgs(endpointsFile);

    // If the endpoints file is empty (e.g. Katana found nothing on a JS-heavy SPA),
    // fall back to scanning the root target URL directly.
    const fileContent = require('fs').readFileSync(endpointsFile, 'utf-8').trim();
    if (!fileContent && fallbackTarget) {
      log.warn(`Endpoints file is empty — falling back to scanning root target: ${fallbackTarget}`);
      require('fs').writeFileSync(endpointsFile, fallbackTarget + '\n', 'utf-8');
    }

    log.info(`Running Nuclei against merged endpoints (severities: ${this.config.severities.join(', ')})`);

    await withRetry(
      () => run('nuclei', args, { timeoutMs: (this.config.timeoutSeconds || 900) * 1000 }),
      // A failure that took the full timeout to occur is a hang, not a transient blip -
      // retrying repeats the same wait for the same outcome instead of failing fast.
      { retries: 2, label: 'nuclei scan', shouldRetry: (err) => !err.message.includes('timed out') }
    );

    const findings = this.parseJsonl(jsonOut);
    log.success(`Nuclei found ${findings.length} results`);

    return { findings, jsonOut: exists(jsonOut) ? jsonOut : null, sarifOut: exists(sarifOut) ? sarifOut : null, skipped: false };
  }

  parseJsonl(jsonlPath) {
    if (!exists(jsonlPath)) return [];
    const lines = fs.readFileSync(jsonlPath, 'utf-8').split('\n').filter(Boolean);
    const findings = [];
    for (const line of lines) {
      try {
        findings.push(JSON.parse(line));
      } catch (err) {
        log.debug(`Skipping malformed Nuclei JSONL line: ${err.message}`);
      }
    }
    return findings;
  }
}

module.exports = { NucleiRunner };
