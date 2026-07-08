'use strict';

const COLORS = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 };

class Logger {
  constructor(scope = 'core', level = process.env.SF_LOG_LEVEL || 'info') {
    this.scope = scope;
    this.level = LEVELS[level] !== undefined ? level : 'info';
  }

  _shouldLog(level) {
    return LEVELS[level] >= LEVELS[this.level];
  }

  _timestamp() {
    return new Date().toISOString();
  }

  _write(color, tag, level, message) {
    if (!this._shouldLog(level)) return;
    const prefix = `${COLORS.dim}${this._timestamp()}${COLORS.reset} ${color}[${tag}]${COLORS.reset} ${COLORS.dim}(${this.scope})${COLORS.reset}`;
    // eslint-disable-next-line no-console
    console.log(`${prefix} ${message}`);
  }

  debug(message) {
    this._write(COLORS.cyan, 'DEBUG', 'debug', message);
  }

  info(message) {
    this._write(COLORS.blue, 'INFO', 'info', message);
  }

  success(message) {
    this._write(COLORS.green, 'OK', 'info', message);
  }

  warn(message) {
    this._write(COLORS.yellow, 'WARN', 'warn', message);
  }

  error(message) {
    this._write(COLORS.red, 'ERROR', 'error', message);
  }

  step(step, total, message) {
    this._write(COLORS.magenta, `STEP ${step}/${total}`, 'info', message);
  }

  child(scope) {
    return new Logger(`${this.scope}:${scope}`, this.level);
  }
}

module.exports = { Logger, defaultLogger: new Logger('security-framework') };
