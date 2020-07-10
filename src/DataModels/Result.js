import Report from './Report.js';
import Vulnerability from './Vulnerability.js';
import { logger, LogLevels } from '../Util';

export default class Result {
  #report;

  #dependencyCount = 0;
  #devDependencyCount = 0;
  #optionalDependencyCount = 0;

  #vulnerabilities = {
    info: [],
    low: [],
    moderate: [],
    high: [],
    critical: []
  };

  #paths = {
    info: 0,
    low: 0,
    moderate: 0,
    high: 0,
    critical: 0,
    total: 0
  };

  static #severities = {
    info: 'Info',
    low: 'Low',
    moderate: 'Medium',
    high: 'High',
    critical: 'Critical'
  };

  /**
   * Convert data from NPM Audit command into gitlab-ci scan report format.
   *
   * @param {Audit} data
   * @param {object} me              Package json for the scanner.
   * @param {object} packageData     Target package.json.
   * @param {object} packageLockData Target lockfile.
   * @return {Promise<Result>}
   */
  static async convert (data, me, packageData, packageLockData) {
    const result = new Result();
    await logger(LogLevels.debug, 'Generating base values...');

    const scanner = me.meta.scanner;
    await logger(LogLevels.debug, 'Scanner created.');
    scanner.version = me.version;

    await logger(LogLevels.debug, `Scanner version set: ${scanner.version}`);

    await logger(LogLevels.debug, 'Generating vulnerabilities.');
    const all = Object.values(data.advisories).map(
      v => Result.#createVulnerability(v, scanner)
    );

    await logger(LogLevels.debug, 'Filtering vulnerabilities by severity.');
    for (const severity of Object.keys(result.#vulnerabilities)) {
      const sev = this.#severities[severity];
      result.#vulnerabilities[severity] = all.filter(s => s.severity === sev);
    }

    result.#dependencyCount = data.metadata.dependencies;
    result.#devDependencyCount = data.metadata.devDependencies;
    result.#optionalDependencyCount = data.metadata.optionalDependencies;

    const { info, low, moderate, high, critical } = data.metadata.vulnerabilities;

    result.#paths.info = info;
    result.#paths.low = low;
    result.#paths.moderate = moderate;
    result.#paths.high = high;
    result.#paths.critical = critical;
    result.#paths.total = (info + low + moderate + high + critical);

    await logger(LogLevels.debug, 'Creating report.');

    result.#report = new Report(all, packageData, packageLockData);
    await logger(LogLevels.debug, 'Done creating report, returning result.');
    return result;
  }

  /**
   * @param {Advisory} advisory  Advisory to create.
   * @param {object} scanner     Current scanner info.
   * @return {Vulnerability}
   */
  static #createVulnerability = (advisory, scanner) => {
    // Set up base data that have to be parsed and is used multiple times.
    const findings = advisory?.findings && advisory?.findings.length > 0 ? advisory.findings : [null];
    // eslint-disable-next-line camelcase
    const packageName = advisory?.module_name ?? 'Unknown';

    const vulnerability = new Vulnerability('package-lock.json', packageName, findings[0]?.version ?? 'Unknown', scanner);
    vulnerability.category = 'Dependency Scanning';
    vulnerability.name = advisory?.title ?? 'Unknown';
    vulnerability.description = advisory?.overview ?? 'N/A';
    vulnerability.message = `${advisory?.title ?? 'Unknown'} in ${packageName}`;
    vulnerability.url = advisory?.url;
    vulnerability.severity = Result.#severities[advisory?.severity] ?? 'Unknown';
    vulnerability.solution = advisory?.recommendation;

    // cve entry is actually deprecated, but the object won't pass schema validation without it.
    vulnerability.cve = advisory?.cves.length > 0 ? advisory.cves[0] : advisory?.cwe ?? 'Unknown';

    // Set up primary identifiers (which is the cwe entry that is intended to always be passed in the audit data.
    vulnerability.identifiers.push({
      url: `https://cwe.mitre.org/data/definitions/${advisory?.cwe?.split('-').pop() ?? 'error'}.html`,
      value: `cwe-${advisory?.cwe ?? packageName}-${findings[0]?.version ?? 'unknown'}-${advisory?.title ?? 'unknown'}`.replace(' ', '-').toLowerCase(),
      type: 'cwe',
      name: advisory?.cwe ?? 'Unknown'
    });
    // And primary link (will also include all extra links after that.
    vulnerability.links.push({
      name: 'NPM advisories',
      url: advisory?.url
    }, {
      name: 'Mitre CWE database',
      url: `https://cwe.mitre.org/data/definitions/${advisory?.cwe?.split('-').pop() ?? 'error'}.html`
    });

    if (advisory?.cves.length > 0) {
      for (const cve of advisory.cves) {
        vulnerability.identifiers.push({
          url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`,
          value: `cve-${cve}-${packageName}-${findings[0]?.version ?? 'Unknown'}-${advisory?.title ?? 'Unknown'}`,
          type: 'cve',
          name: cve
        });

        vulnerability.links.push({
          name: 'Mitre CVE Database',
          url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`
        });
      }
    }
    return vulnerability;
  };

  /**
   * Get all info vulnerabilities.
   * @return {array}
   */
  get info () {
    return this.#vulnerabilities.info;
  }

  /**
   * Get all low vulnerabilities.
   * @return {array}
   */
  get low () {
    return this.#vulnerabilities.low;
  }

  /**
   * Get all moderate vulnerabilities.
   * @return {array}
   */
  get moderate () {
    return this.#vulnerabilities.moderate;
  }

  /**
   * Get all high vulnerabilities.
   * @return {array}
   */
  get high () {
    return this.#vulnerabilities.high;
  }

  /**
   * Get all critical vulnerabilities.
   * @return {array}
   */
  get critical () {
    return this.#vulnerabilities.critical;
  }

  /**
   * Number of total vulnerabilities.
   *
   * @return {number}
   */
  get vulnerabilityCount () {
    return (
      this.#vulnerabilities.critical.length +
      this.#vulnerabilities.high.length +
      this.#vulnerabilities.moderate.length +
      this.#vulnerabilities.low.length +
      this.#vulnerabilities.info.length
    );
  }

  /**
   * @return {{high: number, total: number, critical: number, low: number, info: number, moderate: number}}
   */
  get paths () {
    return this.#paths;
  }

  /**
   * @return {Report}
   */
  get report () {
    return this.#report;
  }

  get optionalDependencyCount () {
    return this.#optionalDependencyCount;
  }

  /**
   * @return {number}
   */
  get devDependencyCount () {
    return this.#devDependencyCount;
  }

  /**
   * @return {number}
   */
  get dependencyCount () {
    return this.#dependencyCount;
  }

  /**
   * @return {number}
   */
  get totalDependencyCount () {
    return this.#devDependencyCount + this.#optionalDependencyCount + this.#devDependencyCount;
  }
}
