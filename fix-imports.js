const fs = require('fs');
const path = require('path');

function processDir(dir) {
  const files = fs.readdirSync(dir);
  for (const f of files) {
    const full = path.join(dir, f);
    if (fs.statSync(full).isDirectory()) {
      if (f !== 'node_modules' && f !== '.git' && f !== 'dist') processDir(full);
    } else if (full.endsWith('.ts')) {
      let content = fs.readFileSync(full, 'utf8');
      let changed = false;
      
      // Replace imports from '../src/...' with '../core/...'
      const newContent = content.replace(/from\s+['"]([^'"]+)['"]/g, (match, p1) => {
        let newPath = p1;
        newPath = newPath.replace(/\.\.\/src\//g, '../core/');
        newPath = newPath.replace(/\.\.\/daemon\//g, '../node/');
        return `from '${newPath}'`;
      });
      
      if (newContent !== content) {
        fs.writeFileSync(full, newContent);
        console.log(`Updated imports in ${full}`);
      }
    }
  }
}

processDir(__dirname);
console.log('Done fixing imports.');
