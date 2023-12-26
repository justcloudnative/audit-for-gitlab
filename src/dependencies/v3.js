// noinspection DuplicatedCode v2 and v3 looks the same, but I wanted to split them up.

import { hasOwn } from '../Util';

export default function process (lockFile) {
  const dependencies = [];
  for (const name in lockFile.packages) {
    if (name === '') {
      continue;
    }

    if (hasOwn(lockFile.packages, name) && 'version' in lockFile.packages[name]) {
      dependencies.push(
        {
          package: {
            name
          },
          version: lockFile.packages[name].version
        }
      );
    }
  }

  return dependencies;
}
