'use strict';

const path = require('path');
const fs = require('fs');
const { readJson } = require('./utils/fsHelpers');

const DEFAULT_CONFIG_PATH = path.join(__dirname, '..', 'config', 'default.config.json');

// Conventional project config filenames, checked in this order in the caller's cwd -
// lets a host project just run `security-framework scan` with no arguments, the same
// way eslint/prettier/jest auto-discover their own config files.
const PROJECT_CONFIG_FILENAMES = [
  'security-framework.config.json',
  '.security-framework.json'
];

/** Look for a conventional config file in `cwd`. Returns its path, or null if none exists. */
function findProjectConfigFile(cwd = process.cwd()) {
  for (const filename of PROJECT_CONFIG_FILENAMES) {
    const candidate = path.join(cwd, filename);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/** Deep merge helper: source overrides target, arrays are replaced not merged. */
function deepMerge(target, source) {
  if (source === null || source === undefined) return target;
  const output = { ...target };
  for (const key of Object.keys(source)) {
    const sourceVal = source[key];
    const targetVal = target[key];
    if (
      sourceVal &&
      typeof sourceVal === 'object' &&
      !Array.isArray(sourceVal) &&
      targetVal &&
      typeof targetVal === 'object' &&
      !Array.isArray(targetVal)
    ) {
      output[key] = deepMerge(targetVal, sourceVal);
    } else if (sourceVal !== undefined) {
      output[key] = sourceVal;
    }
  }
  return output;
}

function isValidUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (err) {
    return false;
  }
}

const VALID_AUTH_TYPES = ['none', 'basic', 'bearer', 'apiKey', 'form', 'cookie', 'oauth', 'jsonLogin'];

function validate(config) {
  const errors = [];

  if (!config.target) {
    errors.push('Missing required field: "target" (the website URL to scan).');
  } else if (!isValidUrl(config.target)) {
    errors.push(`Invalid "target" URL: ${config.target}`);
  }

  const authType = config.authentication && config.authentication.type;
  if (authType && !VALID_AUTH_TYPES.includes(authType)) {
    errors.push(`Invalid authentication.type "${authType}". Must be one of: ${VALID_AUTH_TYPES.join(', ')}`);
  }

  if (authType === 'basic' && (!config.authentication.username || !config.authentication.password)) {
    errors.push('authentication.type "basic" requires "username" and "password".');
  }
  if (authType === 'bearer' && !config.authentication.token) {
    errors.push('authentication.type "bearer" requires "token".');
  }
  if (authType === 'apiKey' && !config.authentication.apiKeyValue) {
    errors.push('authentication.type "apiKey" requires "apiKeyValue".');
  }
  if (authType === 'form' && (!config.authentication.loginUrl || !config.authentication.username || !config.authentication.password)) {
    errors.push('authentication.type "form" requires "loginUrl", "username", and "password".');
  }
  if (authType === 'cookie' && !config.authentication.cookie) {
    errors.push('authentication.type "cookie" requires "cookie".');
  }
  if (authType === 'jsonLogin' && (!config.authentication.loginUrl || !config.authentication.username || !config.authentication.password)) {
    errors.push('authentication.type "jsonLogin" requires "loginUrl", "username", and "password".');
  }

  if (errors.length) {
    const err = new Error(`Configuration invalid:\n  - ${errors.join('\n  - ')}`);
    err.validationErrors = errors;
    throw err;
  }
}

/**
 * Load and normalize scan configuration from:
 *  - a config file path
 *  - a raw target URL string
 *  - CLI flag overrides
 * Always layered on top of config/default.config.json.
 */
function loadConfig(input, overrides = {}) {
  const defaults = readJson(DEFAULT_CONFIG_PATH);

  let userConfig = {};

  if (typeof input === 'string') {
    if (isValidUrl(input)) {
      userConfig = { target: input };
    } else if (fs.existsSync(input)) {
      userConfig = readJson(path.resolve(input));
    } else {
      throw new Error(`Could not interpret "${input}" as a URL or an existing config file path.`);
    }
  } else if (input && typeof input === 'object') {
    userConfig = input;
  } else {
    // No target/config passed - auto-discover a conventional project config file, the
    // same way `security-framework scan` should just work when run inside a host project.
    const discovered = findProjectConfigFile();
    if (discovered) userConfig = readJson(discovered);
  }

  let merged = deepMerge(defaults, userConfig);
  merged = deepMerge(merged, overrides);

  validate(merged);
  return merged;
}

module.exports = { loadConfig, deepMerge, validate, isValidUrl, findProjectConfigFile, DEFAULT_CONFIG_PATH };
