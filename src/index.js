import { logger, LogLevels, writeFile, getConf, fileExists } from './Util.js';
import audit from './Audit.js';
import { reportFindings, doExit } from './Finalization.js';
import pkg from '../package.json';
import lock from '../package-lock.json';
import Result from './DataModels/Result.js';

audit()
  .then(async d => {
    await logger(LogLevels.debug, 'Converting to gitlab scan data format...');
    const result = await Result.convert(d, pkg, lock);
    await logger(LogLevels.debug, 'Conversion done.');
    return result;
  })
  .then(async d => {
    await logger(LogLevels.debug, 'Writing result to file.');
    await writeFile(getConf('REPORT_FILE', 'gl-dependency-scanning-report.json'), JSON.stringify(d.report, null, 2));
    if (await fileExists('gl-dependency-scanning-report.json')) {
      await logger(LogLevels.debug, 'File created successfully.');
    }
    return d;
  })
  .then(d => reportFindings(d, pkg.version))
  .then(doExit)
  .catch(e => logger(LogLevels.fatal, e.message));
