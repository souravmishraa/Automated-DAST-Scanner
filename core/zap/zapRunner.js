'use strict';

const path = require('path');
const yaml = require('js-yaml');
const { run, withRetry } = require('../utils/exec');
const { writeText, readJson, exists } = require('../utils/fsHelpers');
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

  writePlanFile(target, endpointsJsonFile) {
    // endpointsJsonFile is a host-side path to master-endpoints.json (from the crawler/merger
    // step, carries real per-endpoint HTTP methods) - read it here, on the host, and inline
    // the endpoints into the plan itself. ZAP's own built-in spider is far shallower than
    // Katana's JS-aware crawl, so without this, discovered endpoints never reach the active
    // scanner, and without the method data, POST-only endpoints would only ever be GET'd.
    const endpoints = endpointsJsonFile && exists(endpointsJsonFile) ? readJson(endpointsJsonFile) : [];

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

    try {
      if (this.config.zap.mode === 'docker') {
        await this.runDocker(planPath);
      } else {
        await this.runLocal(planPath);
      }
    } catch (err) {
      // All retries exhausted (real timeout, or the report never appeared across every
      // attempt) - degrade gracefully rather than failing the whole pipeline over one step.
      log.warn(`ZAP scan failed after retries: ${err.message}`);
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

  /**
   * External safety-net timeout for the whole ZAP process, tied to what's actually
   * configured rather than a disconnected flat constant. Covers spider + active scan +
   * a fixed buffer for endpoint seeding, passive-scan-wait, and report generation.
   */
  computeWrapperTimeoutMs() {
    const spiderMin = this.config.zap.spiderMaxDurationMinutes || 10;
    const activeScanMin = this.config.zap.activeScanMaxDurationMinutes || 30;
    const bufferMin = 20;
    return (spiderMin + activeScanMin + bufferMin) * 60 * 1000;
  }

  async runDocker(planPath) {
    // path.resolve() ensures we have an absolute Windows path before WSL conversion.
    // Docker volume mounts require an absolute path; relative paths are misread as volume names.
    const absoluteOutputDir = path.resolve(this.runOutputDir);
    const wslOutputDir = this.toWslPath(absoluteOutputDir);
    const reportPath = path.join(this.runOutputDir, 'zap-report.json');

    // Invoke via `wsl` since Docker is only available through WSL on this host.
    // retries: 3 -> covers two distinct, verified failure modes, both of which leave the
    // process exiting "successfully" (no thrown error) with no report:
    //  1. A docker-client log-streaming race under --rm (fixed below by not using --rm and
    //     reaping the container ourselves instead).
    //  2. A confirmed upstream ZAP/HSQLDB bug (zaproxy/zaproxy#6719) where ZAP's internal
    //     history database intermittently closes its connection mid-activeScan, causing every
    //     scan rule to silently complete with 0 messages/alerts - not caused by anything in
    //     this codebase, and not something we can fix from the outside. Retrying with a fresh
    //     container (fresh HSQLDB instance) resolves it most of the time in practice.
    // Neither failure mode makes `run()` reject (exit code is a "successful" 2, not a spawn
    // error), so the retry condition below is driven by report-file presence, not by fn()
    // throwing from run() itself - shouldRetry only needs to exempt real timeouts.
    await withRetry(
      async () => {
        // Unique name instead of --rm: empirically reproduced (repeatedly) that --rm causes
        // the activeScan job to die silently mid-scan on this WSL2/plain-Docker-Engine setup -
        // no exception anywhere (checked ZAP's own internal zap.log, not just console output),
        // no report generated, exit code 2. The exact same plan run without --rm (a --name'd
        // container, cleaned up manually afterward) completes normally most of the time.
        const containerName = `security-framework-zap-${Date.now()}`;
        const args = [
          'docker', 'run', '--name', containerName,
          // Makes host.docker.internal resolve to the host machine from inside the container.
          // Automatic on Docker Desktop, but NOT automatic on plain Docker Engine (e.g. a WSL2
          // Docker Engine install) - verified empirically: this flag is required there for
          // scanning a target that's actually running on the same host (a very common case
          // when testing a locally-running app before it's deployed). Harmless no-op elsewhere.
          '--add-host=host.docker.internal:host-gateway',
          '-v', `${wslOutputDir}:/zap/wrk:rw`,
          this.config.zap.dockerImage || 'zaproxy/zap-stable',
          'zap.sh', '-cmd',
          '-autorun', `/zap/wrk/${path.basename(planPath)}`
        ];

        try {
          await run('wsl', args, { timeoutMs: this.computeWrapperTimeoutMs() });
        } finally {
          // We own cleanup now that --rm is gone - always reap the container, even on
          // failure/timeout, so repeated scans don't leave a trail of stopped containers.
          await run('wsl', ['docker', 'rm', '-f', containerName], { silent: true, timeoutMs: 30000 }).catch(() => {});
        }

        if (!exists(reportPath)) {
          throw new Error(
            'ZAP exited without producing a report (likely the known upstream ZAP/HSQLDB ' +
            'internal-DB race - zaproxy/zaproxy#6719); retrying with a fresh container'
          );
        }
      },
      {
        retries: 3,
        label: 'zap docker scan',
        shouldRetry: (err) => !err.message.includes('timed out')
      }
    );
  }

  async runLocal(planPath) {
    const args = ['-cmd', '-autorun', planPath];
    await withRetry(() => run('zap.sh', args, { timeoutMs: this.computeWrapperTimeoutMs() }), {
      retries: 2,
      label: 'zap local scan',
      shouldRetry: (err) => !err.message.includes('timed out')
    });
  }
}

module.exports = { ZapRunner };
