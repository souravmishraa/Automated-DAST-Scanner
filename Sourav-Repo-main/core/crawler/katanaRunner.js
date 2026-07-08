'use strict';

const path = require('path');
const { run, checkBinaryAvailable } = require('../utils/exec');
const { readLines, writeJson } = require('../utils/fsHelpers');
const { Logger } = require('../utils/logger');

const log = new Logger('katana');

/**
 * Runs Katana against the target and returns a structured list of
 * discovered URLs/endpoints. Requires the `katana` binary on PATH
 * (https://github.com/projectdiscovery/katana).
 */
class KatanaRunner {
  constructor(config, authManager, runOutputDir) {
    this.config = config.crawler.katana;
    this.authManager = authManager;
    this.runOutputDir = runOutputDir;
  }

  async isAvailable() {
    return checkBinaryAvailable('katana', '-version');
  }

  buildArgs(target) {
    const outFile = path.join(this.runOutputDir, 'katana-urls.txt');
    const timeoutSec = this.config.timeoutSeconds || 120;
    const maxPages = this.config.maxPages || 500;
    const args = [
      '-u', target,
      '-d', String(this.config.depth || 3),
      '-c', String(this.config.concurrency || 10),
      '-rl', String(this.config.rateLimit || 150),
      '-ct', `${timeoutSec}s`,  // hard time cap: katana exits gracefully after N seconds
      '-mdp', String(maxPages), // hard page cap: stop after N pages regardless of depth
      '-fsu',                   // filter similar URLs (e.g. /users/1 == /users/2)
      '-o', outFile,
      '-silent',
      '-jc' // include js-crawled endpoints
    ];

    if (this.config.formExtraction) {
      args.push('-fx');
    }
    if (this.config.headless) {
      args.push('-hl');
    }

    for (const header of this.authManager.getHttpHeaders()) {
      args.push('-H', header);
    }

    return { args, outFile };
  }

  async run(target) {
    const available = await this.isAvailable();
    if (!available) {
      log.warn('Katana binary not found on PATH. Skipping crawl step (results will be incomplete).');
      log.warn('Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest');
      return { urls: [], outFile: null, skipped: true };
    }

    const { args, outFile } = this.buildArgs(target);
    log.info(`Crawling ${target} with Katana (depth=${this.config.depth}, jsCrawl=${this.config.jsCrawl})`);

    const timeoutSec = this.config.timeoutSeconds || 120;
    // Katana's own -ct is a soft cutoff: it stops enqueueing new requests at that mark but
    // keeps draining in-flight ones, which empirically can take 2-3x longer to actually exit.
    // Give it a generous grace window before this wrapper force-kills it - on Windows, a forced
    // kill is an unconditional TerminateProcess with no chance to flush the -o output file, so a
    // tight external timeout turns every crawl into zero results instead of a partial one.
    const hardTimeoutMs = timeoutSec * 1000 * 3 + 60000;
    try {
      await run('katana', args, { timeoutMs: hardTimeoutMs });
    } catch (err) {
      if (err.message && err.message.includes('timed out')) {
        // Use whatever URLs were written to disk before the timeout (partial crawl).
        log.warn(`Katana did not finish draining within ${Math.round(hardTimeoutMs / 1000)}s of being asked to stop after ${timeoutSec}s — using partial results.`);
      } else {
        throw err; // re-throw unexpected errors
      }
    }

    const urls = readLines(outFile).filter(Boolean);
    log.success(`Katana discovered ${urls.length} URLs`);

    const structured = urls.map((url) => ({ url, source: 'katana' }));
    writeJson(path.join(this.runOutputDir, 'urls.json'), structured);

    return { urls: structured, outFile, skipped: false };
  }
}

module.exports = { KatanaRunner };
