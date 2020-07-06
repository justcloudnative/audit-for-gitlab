#!/usr/bin/env node
import { promises as fs } from 'fs';
import { exec } from 'child_process';
let exitCode = 0;

const severities = {
  info: 'Info', low: 'Low', moderate: 'Medium', high: 'High', critical: 'Critical'
};

const arrayFirst = function (arr, def = null) {
  return arr !== null && arr.length > 0 ? arr[0] : def;
};

const arrayLast = function (arr, def = null) {
  return arr !== null && arr.length > 0 ? arr[arr.length - 1] : def;
};

const getAudit = async () => {
  return new Promise((resolve, reject) => {
    exec(`cd ${process.cwd()} && npm audit --json`, async (e, stdout, stderr) => {
      return resolve(JSON.parse(stdout));
    });
  });
};

const putFile = async (json) => {
  await fs.writeFile(
    'gl-dependency-scanning-report.json',
    JSON.stringify(json, null, 2)
  );
};

const writeLine = async (type, message) => {
  return new Promise((resolve, reject) => {
    process[type].write(message + '\n', () => {
      resolve();
    });
  });
};

const convertToGl = async (data) => {
  const vulnerabilities = data.metadata.vulnerabilities;
  exitCode = (vulnerabilities.critical > 0 || vulnerabilities.high > 0 || vulnerabilities.moderate > 0) ? 1 : 0;

  // Print out what type of vulnerabilities that affects the project.
  const totalVulns = (vulnerabilities.info + vulnerabilities.low + vulnerabilities.moderate + vulnerabilities.high + vulnerabilities.critical);
  await writeLine('stdout', `Found ${totalVulns} vulnerabilities in ${data.metadata.totalDependencies} dependencies.`);
  await writeLine('stdout', `\tCritical: ${vulnerabilities.critical}`);
  await writeLine('stdout', `\tHigh:     ${vulnerabilities.high}`);
  await writeLine('stdout', `\tModerate: ${vulnerabilities.moderate}`);
  await writeLine('stdout', `\tLow:      ${vulnerabilities.low}`);
  await writeLine('stdout', `\tInfo:     ${vulnerabilities.info}`);

  const advisories = data.advisories;
  return Object.keys(advisories).map((key) => {
    const val = advisories[key];
    const findings = val?.findings && val.findings.length > 0 ? val.findings : [null];
    const packageName = arrayLast(arrayFirst(findings[0]?.paths)?.split('>')) ?? 'Unknown';
    return {
      location: {
        dependency: {
          package: {
            name: packageName,
            version: findings[0]?.version ?? 'Unknown'
          }
        }
      },
      name: val.title,
      message: `${val?.title} in ${packageName}`,
      description: val?.overview,
      cve: val?.cves.length > 0 ? val?.cves[0] : null,
      cwe: val?.cwe,
      solution: val?.recommendation,
      url: val?.url,
      priority: severities[val?.severity] ?? 'Unknown'
    };
  });
};

const doExit = async () => {
  await writeLine('stdout', `Exiting with exit code ${exitCode}`);
  process.exit(exitCode);
};

getAudit().then(convertToGl).then(putFile).then(doExit).catch(async e => {
  await writeLine('stderr', e.message);
});
