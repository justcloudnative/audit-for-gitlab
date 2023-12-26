import { logger, LogLevels } from '../Util';

/**
 * @typedef DependencyInterface
 * @param {{name: string}} package
 * @param {string} version
 */

import v1 from './v1';
import v2 from './v2';
import v3 from './v3';

/**
 * @param {object|{lockfileVersion: number|undefined}} lockFile
 * @returns number
 */
function getLockfileVersion (lockFile) {
  if (lockFile.lockfileVersion === undefined) {
    return 1;
  }

  return lockFile.lockfileVersion;
}

/**
 *
 * @param {object} lockFile Lockfile to process.
 * @returns {Promise<Array<DependencyInterface>>} List of dependencies.
 */
export default async function getDependencies (lockFile) {
  const version = getLockfileVersion(lockFile);

  await logger(LogLevels.info, `PackageLock version ${version}`);
  switch (version) {
    case 1:
      return v1(lockFile);
    case 2:
      return v2(lockFile);
    case 3:
      return v3(lockFile);
    default:
      throw new Error('Invalid lockfile version');
  }
}
