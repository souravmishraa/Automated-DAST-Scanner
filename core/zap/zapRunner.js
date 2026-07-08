'use strict';

const path = require('path');
const yaml = require('js-yaml');
const { run, withRetry } = require('../utils/exec');
const { writeText, readJson, exists, readLines } = require('../utils/fsHelpers');
const { buildZapPlan } = require('./zapPlanBuilder');
const { Logger } = require('../utils/logger');

const log = new Logger('zap');

/**
 * Orchestrates OWASP ZAP in headless Automation Framework mode.
 * Supports two execution modes (config.zap.mode):
 *  - "docker": runs `zaproxy/zap-stable` via the docker CLI (default, no
 *              local ZAP install required)
 *  - "local":  runs a local `zap.sh` / `zap.bat` on PATH
 */
class ZapRunner {
  constructor(config, authManager, runOutputDir) {
    this.config = config;
    this.authManager = authManager;
    this.runOutputDir = runOutputDir;
  }

  async isAvailable() {
    if (this.config.zap.mode === 'docker') {
      // Docker is accessed via WSL on this system (no native Docker on Windows PATH).
      // Use run() directly because checkBinaryAvailable() only accepts a string flag.
      try {
        const result = await run('wsl', ['docker', '--version'], { silent: true, timeoutMs: 10000 });
        return result.code === 0 || result.code === null;
      } catch (err) {
        return false;
      }
    }
    try {
      const result = await run('zap.sh', ['-version'], { silent: true, timeoutMs: 10000 });
      return result.code === 0 || result.code === null;
    } catch (err) {
      return false;
    }
  }

  /**
   * Converts a Windows absolute path to its WSL /mnt/ equivalent.
   * e.g. C:\Users\foo\bar  ->  /mnt/c/Users/foo/bar
   */
  toWslPath(winPath) {
    return winPath
      .replace(/\\/g, '/')
      .replace(/^([A-Za-z]):/, (_, drive) => `/mnt/${drive.toLowerCase()}`);
  }

  writePlanFile(target, endpointsFile) {
    // endpointsFile is a host-side path (master-endpoints.txt from the crawler/merger
    // step) - read it here, on the host, and inline the URLs into the plan itself.
    // ZAP's own built-in spider is far shallower than Katana's JS-aware crawl, so without
    // this, all the endpoints Katana/Swagger discovered never reach the active scanner.
    const endpoints = endpointsFile && exists(endpointsFile) ? readLines(endpointsFile) : [];

    const plan = buildZapPlan({
      target,
      config: this.config,
      authManager: this.authManager,
      endpoints,
      runOutputDir: '/zap/wrk' // path as seen inside the container
    });

    const planYaml = yaml.dump(plan, { noRefs: true, lineWidth: 120 });
    const planPath = path.join(this.runOutputDir, 'zap-plan.yaml');
    writeText(planPath, planYaml);
    log.info(`Generated ZAP automation plan at ${planPath}`);
    return planPath;
  }

  async run(target, endpointsFile) {
    const available = await this.isAvailable();
    if (!available) {
      log.warn(
        `ZAP execution backend ("${this.config.zap.mode}") not available. Skipping ZAP scan (results will be incomplete).`
      );
      log.warn('Install Docker (https://docker.com) or ZAP (https://www.zaproxy.org/download/) to enable this step.');
      return { reportPath: null, sarifPath: null, skipped: true };
    }

    const planPath = this.writePlanFile(target, endpointsFile);

    log.info(`Running OWASP ZAP against ${target} (passive=${this.config.zap.passiveScan}, active=${this.config.zap.activeScan})`);

    if (this.config.zap.mode === 'docker') {
      await this.runDocker(planPath);
    } else {
      await this.runLocal(planPath);
    }

    const reportPath = path.join(this.runOutputDir, 'zap-report.json');
    const sarifPath = path.join(this.runOutputDir, 'zap-report.sarif.json');

    if (!exists(reportPath)) {
      log.warn('ZAP did not produce the expected JSON report. Continuing with empty ZAP findings.');
      return { reportPath: null, sarifPath: null, skipped: true };
    }

    log.success('ZAP scan complete.');
    return { reportPath, sarifPath: exists(sarifPath) ? sarifPath : null, skipped: false };
  }

  async runDocker(planPath) {
    // path.resolve() ensures we have an absolute Windows path before WSL conversion.
    // Docker volume mounts require an absolute path; relative paths are misread as volume names.
    const absoluteOutputDir = path.resolve(this.runOutputDir);
    const wslOutputDir = this.toWslPath(absoluteOutputDir);

    const args = [
      'docker', 'run', '--rm',
      '-v', `${wslOutputDir}:/zap/wrk:rw`,
      this.config.zap.dockerImage || 'zaproxy/zap-stable',
      'zap.sh', '-cmd',
      '-autorun', `/zap/wrk/${path.basename(planPath)}`
    ];

    // Invoke via `wsl` since Docker is only available through WSL on this host.
    // retries: 2 -> one real retry, since a `docker run` immediately after an implicit
    // image pull can transiently fail (e.g. "unable to upgrade to tcp, received 404").
    await withRetry(() => run('wsl', args, { timeoutMs: 60 * 60 * 1000 }), {
      retries: 2,
      label: 'zap docker scan'
    });
  }

  async runLocal(planPath) {
    const args = ['-cmd', '-autorun', planPath];
    await withRetry(() => run('zap.sh', args, { timeoutMs: 60 * 60 * 1000 }), {
      retries: 2,
      label: 'zap local scan'
    });
  }
}

module.exports = { ZapRunner };
