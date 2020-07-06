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

const convertToGl = (data) => {
  const vulnerabilities = data.metadata.vulnerabilities;
  exitCode = (vulnerabilities.critical > 0 || vulnerabilities.high > 0 || vulnerabilities.moderate > 0) ? 1 : 0;
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

const doExit = () => {
  if (exitCode !== 0) {
    process.exit(exitCode);
  }
};

getAudit().then(convertToGl).then(putFile).then(doExit).catch(e => {
  process.stderr.write(e.message, (e) => {
    if (e) {
      console.error(e);
    }
  });
});
