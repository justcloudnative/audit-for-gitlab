// Generate CWE json file.
// Download CWE Simplified Mapping zip from mitre: https://cwe.mitre.org/data/csv/1003.csv.zip
// Move cwe csv to the root dir, rename to cwe.csv and execute script.

const fs = require('fs');
const parser = require('csv-parser');

Promise.resolve().then(() => {
  return new Promise((resolve, reject) => {
    const result = [];
    fs.createReadStream('./cwe.csv')
      .pipe(parser())
      .on('data', (d) => result.push(d))
      .on('end', () => resolve(result));
  });
}).then(records => {
  const obj = {};
  for (const rec of records) {
    obj[rec['CWE-ID']] = {
      name: rec['Name'],
      description: rec['Description']
    };
  }
  return obj;
}).then(async (obj) => {
  await fs.promises.writeFile('./src/cwe.json', JSON.stringify(obj));
});

