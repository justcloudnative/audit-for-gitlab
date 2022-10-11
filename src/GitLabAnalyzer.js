import { randomUUID } from 'crypto';
import CWEList from './cwe.json';
import { hasOwn } from './Util';

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
      if (hasOwn(packagelockData.dependencies, name) && 'version' in packagelockData.dependencies[name]) {
        dependencies.push(
          {
            package: {
              name
            },
            version: packagelockData.dependencies[name].version
          }
        );
      }
    }

    const vulns = [];

    for (const vuln in vulnerabilities) {
      if (hasOwn(vulnerabilities, vuln)) {
        const obj = vulnerabilities[vuln];
        const via = obj.via.shift();

        if (typeof via !== 'object') {
          continue; // TODO, fix this
        }

        const result = this.#createVulnerability(obj, via);
        if (result !== null) {
          vulns.push(result);
        }
      }
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
   * @return {Object|null}
   */
  #createVulnerability (vuln, via) {
    const packageName = vuln.name;

    const identifiers = (via.cwe ?? []).map(cwe => ({
      type: 'cwe',
      name: cwe,
      value: `${cwe}-${packageName}`,
      url: `https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`
    }));

    if (identifiers.length === 0) {
      return null;
    }

    let solution = [];
    if (vuln.fixAvailable) {
      if (vuln.fixAvailable === true) {
        solution = [`Update package ${packageName} to version outside of range ${vuln.range}`];
      } else {
        solution = [`Update package ${vuln.fixAvailable.name} to version ${vuln.fixAvailable.version}`];
      }
    }

    const cweNumber = parseInt(identifiers[0].name.replace('CWE-', ''));
    let cweData = {
      name: `${identifiers[0].name} (in ${packageName})`,
      description: ''
    };

    if (cweNumber in CWEList) {
      if (hasOwn(CWEList, cweNumber)) {
        cweData = {
          name: CWEList[cweNumber].name,
          description: CWEList[cweNumber].description
        };

        cweData.name = `${cweData.name} (in ${packageName})`;
      }
    }

    return {
      id: randomUUID(),
      name: cweData.name,
      description: cweData.description,
      severity: hasOwn(GitLabAnalyzer.#severities, vuln.severity)
        ? GitLabAnalyzer.#severities[vuln.severity]
        : 'Unknown',
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
      remediations: solution
    };
  }
}
