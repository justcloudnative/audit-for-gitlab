import Result from './DataModels/Result.js';
import { logger, LogLevels } from './Util';

/**
 * Convert npm audit format to gitlab report format.
 *
 * @param {Audit} data Data to convert.
 * @param {object} packageFile Package.json file.
 * @param {object} lockFile    Package-lock.json file.
 * @return {Promise<Result>}
 */
export default async (data, packageFile, lockFile) => {
  await logger(LogLevels.debug, 'Starting conversion.');
  return Result.convert(data, packageFile, lockFile);
};
