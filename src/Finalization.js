import { getConf, logger, LogLevels } from './Util.js';

/**
 *
 * @param {Result} result
 * @param {string} scannerVersion
 * @return {Promise<Result>}
 */
const reportFindings = async (result, scannerVersion) => {
  await logger(LogLevels.info, `Found ${result.paths.total} paths with vulnerabilities. Project has a total of ${result.totalDependencyCount} dependencies.`);
  await logger(LogLevels.info, `${result.dependencyCount} dependencies, ${result.devDependencyCount} devDependencies, ${result.optionalDependencyCount} optional dependencies.`);
  await logger(LogLevels.info, `A total of ${result.vulnerabilityCount} vulnerabilities was found.`);
  await logger(LogLevels.info, '\nResult:');
  await logger(LogLevels.info, `\t\x1b[4mTotal:    ${result.vulnerabilityCount}\x1b[0m`);
  await logger(LogLevels.info, `\tCritical: ${result.critical.length}`);
  await logger(LogLevels.info, `\tHigh:     ${result.high.length}`);
  await logger(LogLevels.info, `\tModerate: ${result.moderate.length}`);
  await logger(LogLevels.info, `\tLow:      ${result.low.length}`);
  await logger(LogLevels.info, `\tInfo:     ${result.info.length}\n`);
  await logger(LogLevels.info, `Scan completed. Thank you for using Jitesoft NPM Audit scanner (${scannerVersion}) for your scanning needs!`);

  return result;
};

/**
 *
 * @param {Result} result
 * @return {Promise<void>}
 */
const doExit = async (result) => {
  const exitCode = Number.parseInt(
    getConf('SCAN_EXIT_CODE', (result.high.length + result.critical.length + result.moderate.length) > 0 ? 1 : 0),
    10
  );
  await logger(LogLevels.debug, `Exiting with code ${exitCode}`);
  if (exitCode !== 0) {
    await logger(LogLevels.error, `Found vulneabilities with high severity in the scan, exiting with code ${exitCode}`);
  }

  process.exit(exitCode);
};

export {
  reportFindings, doExit
};
