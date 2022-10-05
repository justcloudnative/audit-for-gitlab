import { randomUUID } from 'crypto';

export default class GitLabAnalyzer {
  #scanner;
  #startTime;
  #version;
  #npmVersion;

  static #severities = {
    info: 'Info',
    low: 'Low',
    moderate: 'Medium',
    high: 'High',
    critical: 'Critical'
  };

  constructor (scannerData, startTime, version, npmVersion) {
    this.#scanner = scannerData;
    this.#startTime = startTime;
    this.#version = version;
    this.#npmVersion = npmVersion;
  }

  /**
   * Convert NPMJS audit report into a GitLab dependency scan report.
   *
   * @param vulnerabilities {object}
   * @param packageData {object}
   * @param packagelockData {object}
   * @returns {Promise<object>}
   */
  async convert (vulnerabilities, packageData, packagelockData) {
    const dependencies = [];
    for (const name in packagelockData.dependencies) {
      dependencies.push(
        {
          package: {
            name
          },
          version: packagelockData.dependencies[name].version
        }
      );
    }

    const vulns = [];

    for (const vuln in vulnerabilities) {
      const obj = vulnerabilities[vuln];
      const via = obj.via.shift();

      if (typeof via !== 'object') {
        continue; // TODO, fix this
      }

      vulns.push(this.#createVulnerability(obj, via));
    }

    return {
      version: '15.0.2',
      scan: {
        analyzer: {
          version: this.#version,
          ...this.#scanner
        },
        scanner: {
          id: 'npmjs_audit',
          version: this.#npmVersion,
          name: 'npmjs',
          url: 'https://npmjs.com',
          vendor: {
            name: 'npmjs'
          }
        },
        type: 'dependency_scanning',
        start_time: this.#startTime.toISOString().split('.').shift(),
        end_time: (new Date()).toISOString().split('.').shift(),
        status: 'success'
      },
      dependency_files: [
        {
          path: 'package-lock.json',
          package_manager: 'npm',
          dependencies
        }
      ],
      vulnerabilities: vulns
    };
  }

  /**
   * Create a single vulnerability.
   *
   * @param {IEntry} vuln
   * @param {IVia} via
   */
  #createVulnerability (vuln, via) {
    const packageName = vuln.name;

    const identifiers = (via.cwe ?? []).map(cwe => ({
      type: 'cwe',
      name: cwe,
      value: `${cwe}-${packageName}`,
      url: `https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`
    }));

    let solution = [];
    if (vuln.fixAvailable) {
      if (vuln.fixAvailable === true) {
        solution = [`Update package ${packageName} to version outside of range ${vuln.range}`];
      } else {
        solution = [`Update package ${vuln.fixAvailable.name} to version ${vuln.fixAvailable.version}`];
      }
    }

    return {
      id: randomUUID(),
      name: packageName,
      severity: GitLabAnalyzer.#severities[vuln.severity],
      links: [
        { url: via.url }
      ],
      location: {
        file: 'package-lock.json',
        dependency: {
          package: {
            name: packageName,
            direct: vuln.isDirect,
            dependency_path: vuln.nodes
          },
          version: vuln.range
        }
      },
      identifiers,
      remidations: solution
    };
  }
}
