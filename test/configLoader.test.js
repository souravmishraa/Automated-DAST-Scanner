const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadConfig, validate, isValidUrl } = require('../core/configLoader');
const { runScan } = require('../core');

test('loadConfig accepts a raw URL input', () => {
  const config = loadConfig('https://example.com');
  assert.equal(config.target, 'https://example.com');
});

test('validate rejects invalid auth config values', () => {
  assert.throws(() => validate({ target: 'https://example.com', authentication: { type: 'basic' } }), /requires "username" and "password"/);
});

test('isValidUrl accepts https URLs', () => {
  assert.equal(isValidUrl('https://example.com'), true);
  assert.equal(isValidUrl('ftp://example.com'), false);
});

test('runScan produces reports even when external tools are unavailable', async () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-framework-'));
  const { reportPaths, normalizedResult } = await runScan('https://example.com', { reporting: { outputDir } });

  assert.equal(normalizedResult.summary.total, 0);
  assert.equal(fs.existsSync(reportPaths.html), true);
  assert.equal(fs.existsSync(reportPaths.json), true);
  assert.equal(fs.existsSync(reportPaths.sarif), true);
});
