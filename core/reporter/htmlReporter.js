'use strict';

const fs = require('fs');
const path = require('path');
const { writeText } = require('../utils/fsHelpers');
const { Logger } = require('../utils/logger');

const log = new Logger('html-reporter');

const TEMPLATE_PATH = path.join(__dirname, '..', '..', 'templates', 'report.template.html');

function escapeForScriptTag(json) {
  // Prevent premature </script> termination inside embedded JSON.
  return json.replace(/</g, '\\u003c');
}

function writeHtmlReport(normalizedResult, outputDir, brandingConfig = {}) {
  const template = fs.readFileSync(TEMPLATE_PATH, 'utf-8');

  const companyName = brandingConfig.companyName || 'Security Framework';
  const primaryColor = brandingConfig.primaryColor || '#6366f1';

  const html = template
    .replace(/{{COMPANY_NAME}}/g, companyName)
    .replace(/{{COMPANY_INITIAL}}/g, companyName.trim().charAt(0).toUpperCase() || 'S')
    .replace(/{{PRIMARY_COLOR}}/g, primaryColor)
    .replace(/{{TARGET}}/g, normalizedResult.target || '')
    .replace(/{{SCANNED_AT}}/g, normalizedResult.scannedAt || '')
    .replace(/{{COMPLETED_AT}}/g, normalizedResult.completedAt || '')
    .replace(/{{TOTAL_FINDINGS}}/g, String(normalizedResult.summary.total || 0))
    .replace('{{REPORT_JSON}}', escapeForScriptTag(JSON.stringify(normalizedResult)));

  const filePath = path.join(outputDir, 'report.html');
  writeText(filePath, html);
  log.success(`HTML dashboard report written to ${filePath}`);
  return filePath;
}

module.exports = { writeHtmlReport };
