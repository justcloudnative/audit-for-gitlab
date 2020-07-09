import { exec } from 'child_process';
import { freemem } from 'os';
import { logger, LogLevels } from './Util.js';

/**
 * Run npm-audit via a child_process exec call.
 *
 * @return {Promise<object>}
 */
export default async () => {
  await logger(LogLevels.debug, 'Running audit.');
  return new Promise((resolve, reject) => {
    exec('npm audit --json', { maxBuffer: Math.round(freemem() * 0.85) }, async (e, stdout, stderr) => {
      await logger(LogLevels.debug, 'Audit done.');
      return resolve(JSON.parse(stdout));
    });
  });
};
