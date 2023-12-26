import { hasOwn } from '../Util';

export default function process (lockFile) {
  const dependencies = [];
  for (const name in lockFile.dependencies) {
    if (hasOwn(lockFile.dependencies, name) && 'version' in lockFile.dependencies[name]) {
      dependencies.push(
        {
          package: {
            name
          },
          version: lockFile.dependencies[name].version
        }
      );
    }
  }

  return dependencies;
}
