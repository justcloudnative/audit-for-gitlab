import { promises } from 'fs';
import { exec } from 'child_process';
const writeFile = promises.writeFile;

const severities = {
  info: 'Info', low: 'Low', moderate: 'Medium', high: 'High', critical: 'Critical'
};

//region Super simple ployfills.
Array.prototype.first = function(def = null) {
  return this.length > 0 ? this[0] : def;
};
Array.prototype.last = function (def = null) {
  return this.length > 0 ? this[this.length -1] : def;
};
//endregion

const getAudit = async () => {
  return new Promise((resolve, reject) => {
    exec(`cd ${process.cwd()} && npm audit --json`, async(e, stdout, stderr) => {
      return resolve(JSON.parse(stdout));
    });
  });
};

const putFile = async (json) => {
  await writeFile(
    'gl-dependency-scanning-report.json',
    JSON.stringify(json, null, 2)
  );
};

const convertToGl = (data) => {
  const advisories = data.advisories;
  return Object.keys(advisories).map((key) => {
    const val = advisories[key];
    const findings = val?.findings && val.findings.length > 0 ? val.findings : [null];
    const packageName = findings[0]?.paths.first()?.split('>').last() ?? 'Unknown';
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

getAudit().then(convertToGl).then(putFile).catch(e => {
  process.stderr.write(e.message, (e) => {
    if (e) {
      console.error(e);
    }
  });
});
