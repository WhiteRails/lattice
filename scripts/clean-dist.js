'use strict';

const fs = require('fs');
const path = require('path');

const outputDirectory = path.resolve(__dirname, '..', 'dist');
if (path.basename(outputDirectory) !== 'dist') {
  throw new Error(`refusing to clean unexpected path: ${outputDirectory}`);
}
fs.rmSync(outputDirectory, { recursive: true, force: true });
