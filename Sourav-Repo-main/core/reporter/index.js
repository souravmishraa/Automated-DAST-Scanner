'use strict';

const { writeJsonReport } = require('./jsonReporter');
const { writeSarifReport } = require('./sarifReporter');
const { writeHtmlReport } = require('./htmlReporter');
const { Logger } = require('../utils/logger');

const log = new Logger('reporter');

function generateReports(normalizedResult, reportingConfig) {
  const outputDir = reportingConfig.outputDir;
  const formats = reportingConfig.formats || ['html', 'json', 'sarif'];
  const written = {};

  if (formats.includes('json')) written.json = writeJsonReport(normalizedResult, outputDir);
  if (formats.includes('sarif')) written.sarif = writeSarifReport(normalizedResult, outputDir);
  if (formats.includes('html')) written.html = writeHtmlReport(normalizedResult, outputDir, reportingConfig.branding);

  log.success(`All requested reports generated in ${outputDir}`);
  return written;
}

module.exports = { generateReports };
