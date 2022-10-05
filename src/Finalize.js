import { getConf, logger, LogLevels } from './Util';

/**
 *
 * @param {object} meta
 * @param {string} npmVersion
 * @param {object} packageData
 * @return {Promise<void>}
 */
const reportFindings = async (meta, npmVersion, packageData) => {
  await logger(LogLevels.info, `Found ${meta.vulnerabilities.total} vulnerabilities.`);
  await logger(LogLevels.info, `Project has a total of ${meta.dependencies.total} dependencies.`);
  await logger(LogLevels.info, `\t${meta.dependencies.prod} production.`);
  await logger(LogLevels.info, `\t${meta.dependencies.dev} develop.`);
  await logger(LogLevels.info, `\t${meta.dependencies.optional} optional.`);
  await logger(LogLevels.info, `\t${meta.dependencies.peer} peer.`);
  await logger(LogLevels.info, `\t${meta.dependencies.peerOptional} peer optional.`);
  await logger(LogLevels.info, '\nResult:');
  await logger(LogLevels.info, `\t\x1b[4mTotal:    ${meta.vulnerabilities.total}\x1b[0m`);
  await logger(LogLevels.info, `\tCritical: ${meta.vulnerabilities.critical}`);
  await logger(LogLevels.info, `\tHigh:     ${meta.vulnerabilities.high}`);
  await logger(LogLevels.info, `\tModerate: ${meta.vulnerabilities.moderate}`);
  await logger(LogLevels.info, `\tLow:      ${meta.vulnerabilities.low}`);
  await logger(LogLevels.info, `\tInfo:     ${meta.vulnerabilities.info}\n`);
  await logger(LogLevels.info, `Scan completed. Thank you for using Jitesoft NPM Audit Analyzer (${packageData.version}) with the Npmjs scanner (${npmVersion}) for your scanning needs!`);
};

/**
 *
 * @param {object} vulnerabilities
 * @return {Promise<void>}
 */
const doExit = async (vulnerabilities) => {
  const exitCode = Number.parseInt(
    getConf('SCAN_EXIT_CODE', (vulnerabilities.high + vulnerabilities.critical + vulnerabilities.moderate) > 0 ? 1 : 0),
    10
  );
  await logger(LogLevels.debug, `Exiting with code ${exitCode}`);
  if (exitCode !== 0) {
    await logger(LogLevels.error, `Found vulnerabilities with high severity in the scan, exiting with code ${exitCode}`);
  }

  process.exit(exitCode);
};

export {
  reportFindings, doExit
};
