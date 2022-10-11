import { promises as fs } from 'fs';

const hasOwn = (object, key) => {
  if (Object.hasOwn) {
    return Object.hasOwn(object, key);
  }

  // eslint-disable-next-line no-prototype-builtins
  return object.hasOwnProperty(key);
};

/**
 * Fetch a value from the configuration.
 * In this case, the configuration is fully done by environment variables.
 *
 * @param {string} key Key to look for.
 * @param {any}    def Default value to return in case no key was found.
 * @return {string|null}
 */
const getConf = (key, def = null) => {
  if (hasOwn(process.env, key)) {
    return process.env[key] ?? def;
  }

  return def;
};

/**
 * Check if a given file exists.
 *
 * @param {string} file File to check.
 * @return {Promise<boolean>}
 */
const fileExists = async (file) => {
  try {
    await fs.open(file, 'r');
    return true;
  } catch (e) {
    if (e.code === 'ENOENT') {
      return false;
    }
    throw e;
  }
};

/**
 * Write data to file.
 *
 * @param {string} file File to write to.
 * @param {string} data Data to write to file.
 * @return {Promise<void>}
 */
const writeFile = async (file, data) => {
  return fs.writeFile(file, data);
};

const readFileJson = async (file) => {
  const data = await fs.readFile(file);
  return JSON.parse(data);
};

const stdout = async (message) => {
  return new Promise((resolve, reject) => {
    process.stdout.write(message + '\n', () => {
      resolve();
    });
  });
};

const stderr = async (message) => {
  return new Promise((resolve, reject) => {
    process.stderr.write(message + '\n', () => {
      resolve();
    });
  });
};

const logLevels = {
  fatal: stderr,
  error: stderr,
  warn: stdout,
  info: stdout,
  debug: stdout
};

const LogLevels = {
  fatal: 'fatal',
  error: 'error',
  warn: 'warn',
  info: 'info',
  debug: 'debug'
};

/**
 * Asynchronously log to stdout or stderr, depending on log-level.
 *
 * Available log levels are:
 * <pre>fatal, error, warn, info, debug</pre>
 *
 * @param {string} level   Level to log.
 * @param {string} message Message to log.
 * @return {Promise<void>}
 */
const logger = async (level, message) => {
  const logLevel = getConf('SECURE_LOG_LEVEL', 'info').toLowerCase();
  const keys = ['fatal', 'error', 'warn', 'info', 'debug'];

  if (keys.includes(logLevel)) {
    logLevels[logLevel](message);
  }
};

export {
  getConf,
  LogLevels,
  logger,
  writeFile,
  fileExists,
  readFileJson,
  hasOwn
};
