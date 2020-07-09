# Audit for GitLab

This is a small script to add a `npm audit` GitLab dependency scanner.  
It generates a JSON audit via npm and converts it to the format that gitlab expects as dep scan report.  

In case a vulnerability equal or higher to `moderate` is found, it will exit with exit code 1, i.e., fail.  
While generating the report, it will also output number of vulnerabilities found (and types) in stdout.

## Usage

Easiest way to use the scanner is to add it as a include in your .gitlab-ci.yml file, such as:

```yaml
include:
  - https://gitlab.com/jitesoft/open-source/javascript/audit-for-gitlab/raw/master/scan.yml
```

This will run the scanning on your project on all events as long as it is disabled via env variables.

If you wish to customize it a bit more, you can extend or write your own:

```yaml
npm-audit_dependency_scanning:
  image: registry.gitlab.com/jitesoft/open-source/javascript/audit-for-gitlab:1
  script:
    - audit-for-gitlab
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

If you wish to just use the scanner in one of your current scripts, the easiest way to do this, is to just install it via NPM:

```sh
npm i --global @jitesoft/audit-for-gitlab
cd /my/project/dir
audit-for-gitlab
cat gl-dependency-scanning-report.json
```

## Dockerfile

The dockerfile is rebuilt on each new version of the scanner released, each build is released for ARM64 and AMD64.  

## Env variables

The following env variables can be used to configure the behaviour of the application slightly:

`SECURE_LOG_LEVEL` - Will change the log level to report more or less output.  
Available levels are: `fatal`, `error`, `warn`, `info`, `debug`though only debug, info and fatal are used in the application.  
The debug level is basically only used for debugging purposes and development. `info` is default.

`SCAN_EXIT_CODE` - Will force a specific exit code in case of a moderate, high or critical vulnerability is found.  
In case this is not set, exit code `1` will be used in the cases above, else `0`.
