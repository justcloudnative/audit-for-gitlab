/**
 * @typedef Audit
 * @property {Object|{Advisory}} advisories
 * @property {MetaData} metadata
 */
/**
 * @typedef Advisory
 * @property {array|null} findings
 * @property {string|null} module_name
 * @property {string|null} title
 * @property {string|null} description
 * @property {string|null} overview
 * @property {string|null} recommendation
 * @property {string|null} cwe
 * @property {string|null} url
 * @property {array<string>|null} cves
 * @property {string|null} severity
 */
/**
 * @typedef MetaData
 * @property {number} dependencies
 * @property {number} devDependencies
 * @property {number} optionalDependencies
 * @property {number} totalDependencies
 * @property {MetaVulnerabilities} vulnerabilities
 */
/**
 * @typedef MetaVulnerabilities
 * @property {number} info
 * @property {number} low
 * @property {number} moderate
 * @property {number} high
 * @property {number} critical
 */
