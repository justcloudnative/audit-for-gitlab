export default class Report {
  version = '2.0.0';
  vulnerabilities = [];
  // eslint-disable-next-line camelcase
  dependency_files = [];

  constructor (vulnerabilities, packageFile, lockFile) {
    this.vulnerabilities = vulnerabilities;
    this.dependency_files = [].concat(
      Object.entries(packageFile.dependencies),
      Object.entries(packageFile.devDependencies)
    ).map(
      d => Report.#createDependency(d[0], d[1])
    );
    this.dependency_files = [].concat(
      this.dependency_files,
      Object.entries(lockFile.dependencies).map(
        d => Report.#createDependency(d[0], d[1].version)
      )
    );
  }

  static #createDependency = (name, version) => {
    return {
      version: version,
      package: {
        name: name
      }
    };
  };
}
