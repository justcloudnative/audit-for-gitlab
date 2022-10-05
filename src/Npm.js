import { exec } from 'child_process';
import { freemem } from 'os';
import { logger, LogLevels } from './Util.js';

/**
 * Run npm-version via a child_process exec call.
 *
 * @return {Promise<object>}
 */
const version = async () => {
  await logger(LogLevels.debug, 'Running audit.');
  return new Promise((resolve, reject) => {
    exec(
      'npm version --json',
      {
        maxBuffer: Math.round(freemem() * 0.85)
      },
      async (e, stdout, stderr) => {
        if (stderr) {
          await logger(LogLevels.error, stderr);
        }
        await logger(LogLevels.debug, 'Audit done.');
        return resolve(JSON.parse(stdout));
      }
    );
  });
};

/**
 * Run npm-audit via a child_process exec call.
 *
 * @return {Promise<object>}
 */
const audit = async () => {
  await logger(LogLevels.debug, 'Running audit.');
  return new Promise((resolve, reject) => {
    exec(
      'npm audit --json',
      {
        maxBuffer: Math.round(freemem() * 0.85)
      },
      async (e, stdout, stderr) => {
        if (stderr) {
          await logger(LogLevels.error, stderr);
        }
        await logger(LogLevels.debug, 'Audit done.');
        return resolve(JSON.parse(stdout));
      }
    );
  });
};

export {
  version,
  audit
};
