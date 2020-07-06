import { freemem } from 'os';
import { promises as fs } from 'fs';
import { exec } from 'child_process';

let exitCode = 0;

const severities = {
  info: 'Info', low: 'Low', moderate: 'Medium', high: 'High', critical: 'Critical'
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

    const deps = Object.entries(require('./package-lock.json').dependencies).map(o => {
      return {
        version: o[1].version,
        package: {
          name: o[0]
        }
      };
    });
    files.push({
      path: 'package-lock.json',
      package_manager: 'npm',
      dependencies: deps
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
    const packageName = val?.module_name ?? 'Unknown';

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
        name: 'NPM Audit scanner by Jitesoft',
        version: require('./package.json').version,
        vendor: {
          name: 'Jitesoft',
          email: 'support@jitesoft.com'
        }
      },
      category: 'Dependency Scanning',
      identifiers: [
        {
          url: `https://cwe.mitre.org/data/definitions/${arrayLast(val?.cwe?.split('-')) ?? 'error'}.html`,
          value: `cwe-${val?.cwe ?? packageName}-${findings[0]?.version ?? 'Unknown'}-${val?.title ?? 'Unknown'}`.replace(' ', '-').toLowerCase(),
          type: 'cwe',
          name: val?.cwe
        }
      ],
      links: [
        {
          name: 'NPM advisories',
          url: val?.url
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
        vuln.links.push({
          name: 'CVE',
          url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${val.cves[i]}`
        });
      }
    }

    return vuln;
  });

  // Print out what type of vulnerabilities that affects the project.
  const totalVulns = (vulnerabilities.info + vulnerabilities.low + vulnerabilities.moderate + vulnerabilities.high + vulnerabilities.critical);
  if (getLogLevel() <= 1) {
    await writeLine('stdout', `Found ${totalVulns} paths with vulnerabilities. Project has ${data.metadata.totalDependencies} dependencies.`);
    await writeLine('stdout', `A total of ${vulnCount.total} vulnerabilities was found in ${Object.keys(packages).length} dependency.`);
    await writeLine('stdout', '\nResult:');
    await writeLine('stdout', `\t\x1b[4mTotal:    ${vulnCount.total}\x1b[0m`);
    await writeLine('stdout', `\tCritical: ${vulnCount.critical}`);
    await writeLine('stdout', `\tHigh:     ${vulnCount.high}`);
    await writeLine('stdout', `\tModerate: ${vulnCount.moderate}`);
    await writeLine('stdout', `\tLow:      ${vulnCount.low}`);
    await writeLine('stdout', `\tInfo:     ${vulnCount.info}\n`);
    await writeLine('stdout', `Scan completed. Thank you for using Jitesoft NPM Audit scanner (${require('./package.json').version}) for your scanning needs!`);
  }
  return obj;
};

const getLogLevel = () => {
  switch (process.env.SECURE_LOG_LEVEL) {
    case 'fatal': return 4;
    case 'error': return 3;
    case 'warn': return 2;
    case 'info': return 1;
    case 'debug': return 0;
    default: return 1;
  }
};

const doExit = async () => {
  if (getLogLevel() <= 1) {
    await writeLine('stdout', `Exiting with exit code ${exitCode}`);
  }
  process.exit(exitCode);
};

getAudit().then(convertToGl).then(putFile).then(doExit).catch(async e => {
  await writeLine('stderr', e.message);
});
