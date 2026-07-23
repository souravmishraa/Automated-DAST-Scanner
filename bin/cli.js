#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const { Command } = require('commander');
const { runScan, computeExitCode } = require('../core/index');
const { loadConfig, findProjectConfigFile } = require('../core/configLoader');
const { generateReports } = require('../core/reporter');
const { readJson } = require('../core/utils/fsHelpers');
const { Logger } = require('../core/utils/logger');
const pkg = require('../package.json');

const log = new Logger('cli');
const program = new Command();

program
  .name('security-framework')
  .description('Plug-and-play website security scanning framework (Katana + OWASP ZAP + Nuclei)')
  .version(pkg.version);

program
  .command('scan [targetOrConfig]')
  .description('Run a full scan against a URL or a config.json file')
  .option('--target <url>', 'Target website URL (overrides config/positional arg)')
  .option('--auth <path>', 'Path to a JSON file containing just the "authentication" block')
  .option('--fail-on <severity>', 'Exit non-zero if findings at/above this severity exist (critical|high|medium|low|info|none)')
  .option('--output <dir>', 'Base output directory (default ./output)')
  .option('--no-active-scan', 'Disable ZAP active scanning (passive scan only)')
  .option('--no-open', 'Do not automatically open the HTML report when the scan finishes')
  .action(async (targetOrConfig, cmdOptions) => {
    try {
      const overrides = buildOverrides(cmdOptions);
      const input = cmdOptions.target || targetOrConfig;

      if (!input && !findProjectConfigFile()) {
        log.error(
          'You must supply a target URL or a config file, or place a security-framework.config.json ' +
          'in the current directory. Example: security-framework scan https://example.com'
        );
        process.exitCode = 1;
        return;
      }

      const { normalizedResult, reportPaths, runOutputDir, skippedSteps } = await runScan(input, overrides);

      printSummary(normalizedResult, reportPaths, runOutputDir, skippedSteps);
      if (cmdOptions.open !== false) openInBrowser(reportPaths.html);

      const failOn = overrides.failOn || 'critical';
      process.exitCode = computeExitCode(normalizedResult, failOn);
    } catch (err) {
      log.error(err.message);
      if (process.env.SF_DEBUG) console.error(err.stack);
      process.exitCode = 1;
    }
  });

program
  .command('report <reportJsonPath>')
  .description('Regenerate HTML/SARIF reports from an existing report.json (or normalized JSON)')
  .option('--output <dir>', 'Output directory for regenerated reports (default: same dir as input)')
  .option('--no-open', 'Do not automatically open the HTML report once regenerated')
  .action((reportJsonPath, cmdOptions) => {
    try {
      const resolvedPath = path.resolve(reportJsonPath);
      if (!fs.existsSync(resolvedPath)) {
        throw new Error(`File not found: ${resolvedPath}`);
      }
      const normalizedResult = readJson(resolvedPath);
      const outputDir = cmdOptions.output ? path.resolve(cmdOptions.output) : path.dirname(resolvedPath);

      const reportingConfig = {
        outputDir,
        formats: ['html', 'json', 'sarif'],
        branding: { companyName: 'Security Framework', primaryColor: '#6366f1' }
      };
      const reportPaths = generateReports(normalizedResult, reportingConfig);
      log.success(`Reports regenerated in ${outputDir}`);
      Object.entries(reportPaths).forEach(([fmt, p]) => log.info(`  ${fmt.toUpperCase()}: ${p}`));
      if (cmdOptions.open !== false) openInBrowser(reportPaths.html);
    } catch (err) {
      log.error(err.message);
      process.exitCode = 1;
    }
  });

program
  .command('clean')
  .description('Remove all generated output under ./output')
  .option('--output <dir>', 'Output directory to clean (default ./output)')
  .action((cmdOptions) => {
    const dir = path.resolve(cmdOptions.output || './output');
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
      log.success(`Removed ${dir}`);
    } else {
      log.info(`Nothing to clean at ${dir}`);
    }
  });

program.parse(process.argv);

// ---- helpers ----

function buildOverrides(cmdOptions) {
  const overrides = {};

  if (cmdOptions.target) overrides.target = cmdOptions.target;
  if (cmdOptions.output) overrides.reporting = { outputDir: cmdOptions.output };
  if (cmdOptions.failOn) overrides.failOn = cmdOptions.failOn;
  if (cmdOptions.activeScan === false) overrides.zap = { activeScan: false };

  if (cmdOptions.auth) {
    const authPath = path.resolve(cmdOptions.auth);
    if (!fs.existsSync(authPath)) {
      throw new Error(`--auth file not found: ${authPath}`);
    }
    const authFile = readJson(authPath);
    // Accept either a bare authentication block ({type, ...}) or a full config-shaped
    // file ({target, authentication, failOn}) - unwrapping the latter matters because
    // jamming the whole object into config.authentication leaves it without a "type"
    // field, which AuthManager silently treats as type "none" (scan proceeds
    // unauthenticated with no error).
    const authBlock = authFile.authentication && typeof authFile.authentication === 'object'
      ? authFile.authentication
      : authFile;
    overrides.authentication = authBlock;
    if (authFile.target && !overrides.target) overrides.target = authFile.target;
    if (authFile.failOn && !overrides.failOn) overrides.failOn = authFile.failOn;
  }

  return overrides;
}

function openInBrowser(filePath) {
  if (process.env.CI) return; // no display/browser in CI runners; report is still uploaded as an artifact

  const resolved = path.resolve(filePath);
  const platform = process.platform;
  const command = platform === 'win32'
    ? 'cmd'
    : platform === 'darwin'
      ? 'open'
      : 'xdg-open';
  const args = platform === 'win32' ? ['/c', 'start', '""', resolved] : [resolved];

  execFile(command, args, { windowsVerbatimArguments: platform === 'win32' }, (err) => {
    if (err) log.warn(`Could not auto-open the report (${err.message}). Open it manually: ${resolved}`);
  });
}

function printSummary(normalizedResult, reportPaths, runOutputDir, skippedSteps) {
  const s = normalizedResult.summary;
  console.log('\n' + '─'.repeat(60));
  console.log(`  SCAN SUMMARY: ${normalizedResult.target}`);
  console.log('─'.repeat(60));
  console.log(`  Critical: ${s.critical}   High: ${s.high}   Medium: ${s.medium}   Low: ${s.low}   Info: ${s.info}`);
  console.log(`  Total findings: ${s.total}`);
  console.log('─'.repeat(60));
  console.log(`  HTML report : ${reportPaths.html}`);
  console.log(`  JSON report : ${reportPaths.json}`);
  console.log(`  SARIF report: ${reportPaths.sarif}`);
  console.log('─'.repeat(60));

  const skipped = Object.entries(skippedSteps).filter(([, v]) => v).map(([k]) => k);
  if (skipped.length) {
    console.log(`  NOTE: the following tools were unavailable and skipped: ${skipped.join(', ')}`);
    console.log('  Install them for a complete scan (see README.md).');
    console.log('─'.repeat(60));
  }
  console.log('');
}
