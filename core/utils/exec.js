'use strict';

const { spawn } = require('child_process');
const { Logger } = require('./logger');

const log = new Logger('exec');

/**
 * Run an external CLI command as a child process, streaming output.
 * @param {string} command - binary to execute (e.g. "katana", "nuclei")
 * @param {string[]} args - CLI arguments
 * @param {object} options
 * @param {string} [options.cwd]
 * @param {object} [options.env]
 * @param {number} [options.timeoutMs]
 * @param {boolean} [options.silent] - suppress stdout/stderr passthrough logging
 * @returns {Promise<{code:number, stdout:string, stderr:string}>}
 */
function run(command, args = [], options = {}) {
  const { cwd, env, timeoutMs = 0, silent = false } = options;

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: cwd || process.cwd(),
      env: { ...process.env, ...(env || {}) },
      shell: false,
      // Explicitly close stdin instead of leaving it as an open, un-ended pipe (Node's
      // default). Some CLIs (e.g. Katana) check isatty(stdin) and, finding a non-TTY pipe
      // that never closes, block indefinitely waiting for EOF before doing anything else.
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let timer = null;

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
      }, timeoutMs);
    }

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      if (!silent) process.stdout.write(chunk);
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
      if (!silent) process.stderr.write(chunk);
    });

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      if (err.code === 'ENOENT') {
        reject(new Error(`Binary not found: "${command}". Is it installed and on PATH?`));
      } else {
        reject(err);
      }
    });

    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      if (timedOut) {
        return reject(new Error(`Command "${command}" timed out after ${timeoutMs}ms`));
      }
      resolve({ code, stdout, stderr });
    });
  });
}

/**
 * Retry an async function with exponential backoff.
 * @param {Function} fn - async function to execute
 * @param {object} options
 * @param {number} [options.retries=3]
 * @param {number} [options.baseDelayMs=1000]
 * @param {string} [options.label]
 */
async function withRetry(fn, options = {}) {
  const { retries = 3, baseDelayMs = 1000, label = 'operation' } = options;
  let lastError;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastError = err;
      log.warn(`${label} failed (attempt ${attempt}/${retries}): ${err.message}`);
      if (attempt < retries) {
        const delay = baseDelayMs * Math.pow(2, attempt - 1);
        await new Promise((res) => setTimeout(res, delay));
      }
    }
  }
  throw lastError;
}

/** Check whether a binary exists on PATH by attempting to run its version flag. */
async function checkBinaryAvailable(command, versionFlag = '--version') {
  try {
    const result = await run(command, [versionFlag], { silent: true, timeoutMs: 10000 });
    return result.code === 0 || result.code === null;
  } catch (err) {
    return false;
  }
}

module.exports = { run, withRetry, checkBinaryAvailable };
