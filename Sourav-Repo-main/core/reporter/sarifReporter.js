'use strict';

const path = require('path');
const { writeJson } = require('../utils/fsHelpers');
const { Logger } = require('../utils/logger');

const log = new Logger('sarif-reporter');

const SEVERITY_TO_SARIF_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note'
};

/**
 * Converts the normalized finding schema into a SARIF 2.1.0 document,
 * suitable for `github/codeql-action/upload-sarif`.
 */
function buildSarif(normalizedResult) {
  const rulesMap = new Map();
  const results = [];

  for (const finding of normalizedResult.findings) {
    const ruleId = `${finding.tool}/${finding.category}`.replace(/\s+/g, '-');

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description || finding.title },
        help: { text: finding.recommendation || '' },
        properties: {
          tags: [finding.tool, finding.severity, finding.cwe, finding.cve].filter(Boolean)
        },
        defaultConfiguration: {
          level: SEVERITY_TO_SARIF_LEVEL[finding.severity] || 'note'
        }
      });
    }

    results.push({
      ruleId,
      level: SEVERITY_TO_SARIF_LEVEL[finding.severity] || 'note',
      message: { text: finding.description || finding.title },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.url || normalizedResult.target }
          }
        }
      ],
      properties: {
        severity: finding.severity,
        tool: finding.tool,
        parameter: finding.parameter,
        evidence: finding.evidence,
        cwe: finding.cwe,
        cve: finding.cve
      }
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'security-framework',
            informationUri: 'https://github.com/your-org/security-framework',
            version: '1.0.0',
            rules: [...rulesMap.values()]
          }
        },
        results
      }
    ]
  };
}

function writeSarifReport(normalizedResult, outputDir) {
  const sarif = buildSarif(normalizedResult);
  const filePath = path.join(outputDir, 'report.sarif');
  writeJson(filePath, sarif);
  log.success(`SARIF report written to ${filePath}`);
  return filePath;
}

module.exports = { writeSarifReport, buildSarif };
