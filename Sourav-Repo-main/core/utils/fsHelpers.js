'use strict';

const fs = require('fs');
const path = require('path');

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
  return dirPath;
}

function writeJson(filePath, data) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
  return filePath;
}

function readJson(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(content);
}

function writeText(filePath, text) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, text, 'utf-8');
  return filePath;
}

function exists(filePath) {
  return fs.existsSync(filePath);
}

function readLines(filePath) {
  return fs
    .readFileSync(filePath, 'utf-8')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

/** Build a per-run output directory namespaced by target + timestamp. */
function makeRunOutputDir(baseOutputDir, target) {
  const safeHost = target.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '_');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.join(baseOutputDir, `${safeHost}_${timestamp}`);
  ensureDir(dir);
  return dir;
}

module.exports = { ensureDir, writeJson, readJson, writeText, exists, readLines, makeRunOutputDir };
