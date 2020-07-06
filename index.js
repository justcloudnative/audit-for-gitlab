import { freemem } from 'os';
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
    exec('npm audit --json', { maxBuffer: Math.round(freemem() * 0.85) }, async (e, stdout, stderr) => {
      return resolve(JSON.parse(stdout));
    });
  });
};

const putFile = async (json) => {
  const files = [];
  try {
    await fs.open('package.json', 'r');
    const deps = [].concat(Object.entries(require('./package.json').dependencies), Object.entries(require('./package.json').devDependencies)).map(o => {
      return {
        version: o[1],
        package: {
          name: o[0]
        }
      };
    });

    files.push({
      path: 'package.json',
      package_manager: 'npm',
      dependencies: deps
    });
  } catch (e) {
    // np!
  }
  try {
    await fs.open('package-lock.json', 'r');
    files.push({
      path: 'package-lock.json',
      package_manager: 'npm',
      dependencies: []
    });
  } catch (e) {
    // np!
  }

  await fs.writeFile(
    'gl-dependency-scanning-report.json',
    JSON.stringify({
      version: '2.0.0',
      vulnerabilities: json,
      dependency_files: files
    }, null, 2)
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

  const advisories = data.advisories;

  const vulnCount = {
    info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0
  };
  const packages = {};

  const obj = Object.keys(advisories).map((key) => {
    const val = advisories[key];
    const findings = val?.findings && val.findings.length > 0 ? val.findings : [null];
    const packageName = arrayLast(arrayFirst(findings[0]?.paths)?.split('>')) ?? 'Unknown';

    packages[packageName] = true;
    vulnCount[val?.severity] += 1;
    vulnCount.total += 1;

    const vuln = {
      location: {
        file: 'package-lock.json',
        dependency: {
          package: {
            name: packageName
          },
          version: findings[0]?.version ?? 'Unknown'
        }
      },
      scanner: {
        id: 'jitesoft_npm_scanner',
        name: 'NPM Audit',
        version: require('./package.json').version,
        vendor: {
          name: 'Jitesoft',
          email: 'support@jitesoft.com'
        }
      },
      category: 'Dependency Scanning',
      identifiers: [
        {
          url: val?.url,
          value: `cwe-${packageName}-${findings[0]?.version ?? 'Unknown'}-${val?.title ?? 'Unknown'}`,
          type: 'cwe',
          name: val?.cwe
        }
      ],
      name: val?.title ?? 'Unknown',
      message: `${val?.title} in ${packageName}`,
      description: val?.overview,
      cve: val?.cves.length > 0 ? val.cves[0] : val?.cwe ?? 'Unknown',
      solution: val?.recommendation,
      url: val?.url,
      severity: severities[val?.severity] ?? 'Unknown'
    };

    if (val?.cves.length > 0) {
      for (let i = 0; i < val.cves.length; i++) {
        vuln.identifiers.push({
          url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${val.cves[i]}`,
          value: `cve-${val.cves[i]}-${packageName}-${findings[0]?.version ?? 'Unknown'}-${val?.title ?? 'Unknown'}`,
          type: 'cve',
          name: val.cves[i]
        });
      }
    }

    return vuln;
  });

  // Print out what type of vulnerabilities that affects the project.
  const totalVulns = (vulnerabilities.info + vulnerabilities.low + vulnerabilities.moderate + vulnerabilities.high + vulnerabilities.critical);
  await writeLine('stdout', `Found ${totalVulns} paths with vulnerabilities. Project has ${data.metadata.totalDependencies} dependencies.`);
  await writeLine('stdout', `A total of ${vulnCount.total} vulnerabilities was found in ${Object.keys(packages).length} dependency.`);
  await writeLine('stdout', '\nResult:');
  await writeLine('stdout', `\t\x1b[4mTotal:    ${vulnCount.total}\x1b[0m`);
  await writeLine('stdout', `\tCritical: ${vulnCount.critical}`);
  await writeLine('stdout', `\tHigh:     ${vulnCount.high}`);
  await writeLine('stdout', `\tModerate: ${vulnCount.moderate}`);
  await writeLine('stdout', `\tLow:      ${vulnCount.low}`);
  await writeLine('stdout', `\tInfo:     ${vulnCount.info}\n`);

  return obj;
};

const doExit = async () => {
  await writeLine('stdout', `Exiting with exit code ${exitCode}`);
  process.exit(exitCode);
};

getAudit().then(convertToGl).then(putFile).then(doExit).catch(async e => {
  await writeLine('stderr', e.message);
});
