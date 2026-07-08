'use strict';

const crypto = require('crypto');
const { exists, readJson, writeJson } = require('../utils/fsHelpers');
const fs = require('fs');
const { Logger } = require('../utils/logger');

const log = new Logger('normalizer');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function makeId(tool, url, title) {
  return crypto
    .createHash('sha1')
    .update(`${tool}|${url}|${title}`)
    .digest('hex')
    .slice(0, 16);
}

function normalizeSeverity(raw) {
  if (!raw) return 'info';
  // ZAP's riskdesc format is "Risk (Confidence)" e.g. "Low (High)" - the
  // confidence word must NOT be allowed to shadow the actual risk level, so
  // only the leading risk token (before any parenthesis) is inspected.
  const leading = String(raw).split('(')[0].trim().toLowerCase();
  if (leading.includes('critical')) return 'critical';
  if (leading.includes('high')) return 'high';
  if (leading.includes('medium') || leading.includes('moderate')) return 'medium';
  if (leading.includes('low')) return 'low';
  if (leading.includes('info')) return 'info';
  return 'info';
}

/** Normalize a single ZAP alert (from traditional-json report format) into the common schema. */
function normalizeZapAlert(alert, siteName) {
  return {
    id: makeId('zap', alert.url || siteName, alert.name),
    tool: 'zap',
    severity: normalizeSeverity(alert.riskdesc || alert.risk),
    category: alert.pluginId ? `ZAP-${alert.pluginId}` : 'zap-finding',
    title: alert.name || alert.alert || 'ZAP Finding',
    description: alert.desc || '',
    url: alert.url || siteName,
    parameter: alert.param || null,
    evidence: alert.evidence || null,
    recommendation: alert.solution || '',
    cwe: alert.cweid ? `CWE-${alert.cweid}` : null,
    cve: null,
    references: alert.reference ? alert.reference.split('\n').filter(Boolean) : []
  };
}

function normalizeZapReport(zapReportPath) {
  if (!zapReportPath || !exists(zapReportPath)) return [];
  let data;
  try {
    data = readJson(zapReportPath);
  } catch (err) {
    log.warn(`Could not parse ZAP report: ${err.message}`);
    return [];
  }

  const results = [];
  const sites = data.site || data.Report?.site || [];
  for (const site of Array.isArray(sites) ? sites : [sites]) {
    const alerts = site.alerts || [];
    for (const alert of alerts) {
      const instances = alert.instances && alert.instances.length ? alert.instances : [{ uri: site['@name'] }];
      for (const instance of instances) {
        results.push(
          normalizeZapAlert(
            { ...alert, url: instance.uri, param: instance.param, evidence: instance.evidence },
            site['@name']
          )
        );
      }
    }
  }
  return results;
}

/** Normalize a single Nuclei JSONL finding into the common schema. */
function normalizeNucleiFinding(finding) {
  const info = finding.info || {};
  return {
    id: makeId('nuclei', finding['matched-at'] || finding.host, info.name),
    tool: 'nuclei',
    severity: normalizeSeverity(info.severity),
    category: (info.tags || []).join(', ') || finding['template-id'] || 'nuclei-finding',
    title: info.name || finding['template-id'] || 'Nuclei Finding',
    description: info.description || '',
    url: finding['matched-at'] || finding.host || '',
    parameter: null,
    evidence: finding['extracted-results'] ? finding['extracted-results'].join(', ') : finding.matcher_name || null,
    recommendation: info.remediation || 'Review the finding and apply the relevant vendor patch or mitigation.',
    cwe: (info.classification && info.classification['cwe-id'] && info.classification['cwe-id'][0]) || null,
    cve: (info.classification && info.classification['cve-id'] && info.classification['cve-id'][0]) || null,
    references: info.reference || []
  };
}

function normalizeNucleiFindings(findings) {
  return findings.map(normalizeNucleiFinding);
}

/** Represent Katana discoveries as informational entries (no vuln, just visibility). */
function normalizeKatanaAsInfo(katanaUrls) {
  return katanaUrls.slice(0, 0); // Katana is a discovery tool, not a vuln source - excluded from findings by default.
}

/**
 * Combines ZAP + Nuclei findings into one normalized array, sorted by
 * severity (critical first), and computes summary stats.
 */
function normalizeAll({ zapReportPath, nucleiFindings = [], katanaUrls = [], target, startedAt, finishedAt }) {
  const findings = [
    ...normalizeZapReport(zapReportPath),
    ...normalizeNucleiFindings(nucleiFindings),
    ...normalizeKatanaAsInfo(katanaUrls)
  ];

  // Dedupe identical id (same tool+url+title reported twice)
  const dedupedMap = new Map();
  for (const f of findings) {
    dedupedMap.set(f.id, f);
  }
  const deduped = [...dedupedMap.values()].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: deduped.length };
  for (const f of deduped) summary[f.severity]++;

  log.success(
    `Normalized ${deduped.length} findings (critical=${summary.critical}, high=${summary.high}, medium=${summary.medium}, low=${summary.low}, info=${summary.info})`
  );

  return {
    target,
    scannedAt: startedAt,
    completedAt: finishedAt,
    summary,
    findings: deduped
  };
}

module.exports = { normalizeAll, normalizeZapReport, normalizeNucleiFindings, SEVERITY_ORDER };
