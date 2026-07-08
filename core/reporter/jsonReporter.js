'use strict';

const path = require('path');
const { writeJson } = require('../utils/fsHelpers');
const { Logger } = require('../utils/logger');

const log = new Logger('json-reporter');

function writeJsonReport(normalizedResult, outputDir) {
  const filePath = path.join(outputDir, 'report.json');
  writeJson(filePath, normalizedResult);
  log.success(`JSON report written to ${filePath}`);
  return filePath;
}

module.exports = { writeJsonReport };
