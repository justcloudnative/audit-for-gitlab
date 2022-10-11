import { fileExists, getConf, logger, LogLevels, writeFile, readFileJson } from './Util';
import { audit, version } from './Npm';
import { doExit, reportFindings } from './Finalize';
import packageInfo from '../package.json';
import GitLabAnalyzer from './GitLabAnalyzer';

const startTime = new Date();

audit().then(async auditData => {
  await logger(LogLevels.info, 'Generated audit report from npm');
  await logger(LogLevels.info, 'Converting to gitlab specification');

  const npmVersion = await version();

  const packageFile = await readFileJson(`${process.cwd()}/package.json`);
  const packageLockFile = await readFileJson(`${process.cwd()}/package-lock.json`);

  const result = await (new GitLabAnalyzer(
    packageInfo.meta.scanner,
    startTime,
    packageInfo.version,
    npmVersion.npm
  )).convert(
    auditData.vulnerabilities,
    packageFile,
    packageLockFile
  );

  return {
    npmVersion: npmVersion.npm,
    meta: auditData.metadata,
    result
  };
}).then(async output => {
  await logger(LogLevels.debug, 'Writing result to file.');
  await writeFile(getConf('REPORT_FILE', 'gl-dependency-scanning-report.json'), JSON.stringify(output.result, null, 2));
  if (await fileExists('gl-dependency-scanning-report.json')) {
    await logger(LogLevels.debug, 'File created successfully.');
  }

  return {
    npmVersion: output.npmVersion,
    meta: output.meta
  };
}).then(async data => {
  await reportFindings(data.meta, data.npmVersion, packageInfo);
  await doExit(data.meta.vulnerabilities);
}).catch(e => {
  logger(LogLevels.fatal, e.message);
});
