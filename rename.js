const fs = require('fs');
const path = require('path');

function walk(dir) {
    let results = [];
    const list = fs.readdirSync(dir);
    list.forEach(file => {
        if (file === 'node_modules' || file === '.git' || file === 'dist' || file.endsWith('.jsonl')) return;
        const full = path.join(dir, file);
        const stat = fs.statSync(full);
        if (stat && stat.isDirectory()) {
            results = results.concat(walk(full));
        } else {
            results.push(full);
        }
    });
    return results;
}

const files = walk(__dirname);

for (const file of files) {
    if (file.match(/\.(png|jpg|jpeg|gif|bin|abi|mp4|DS_Store)$/i)) continue;
    if (file === __filename) continue; // Skip self

    let content = fs.readFileSync(file, 'utf8');
    let newContent = content
        // Text / Variables
        .replace(/WhiteNet/g, 'Lattice')
        .replace(/whitenet/g, 'lattice')
        .replace(/WHITENET/g, 'LATTICE')
        .replace(/WhiteChain/g, 'LatticeChain')
        .replace(/WhiteCA/g, 'LatticeCA')
        .replace(/WhiteRegistry/g, 'LatticeRegistry')
        .replace(/WhiteLog/g, 'LatticeLog')
        .replace(/WhiteProtocol/g, 'LatticeProtocol')
        .replace(/WhiteGateway/g, 'LatticeGateway')
        .replace(/White Gateway/g, 'Lattice Gateway')
        // Scheme / TLD
        .replace(/wp:\/\//g, 'lp://')
        .replace(/\.white\b/g, '.lattice');
        
    if (content !== newContent) {
        fs.writeFileSync(file, newContent);
        console.log(`Updated content: ${file}`);
    }
}

// Rename specific files
const renames = [
    ['cli/whitenet.ts', 'cli/lattice.ts'],
    ['tests/whitenet.test.ts', 'tests/lattice.test.ts'],
    ['specs/whitenet-whitepaper.md', 'specs/lattice-whitepaper.md'] // If it still exists
];

for (const [oldName, newName] of renames) {
    const oldPath = path.join(__dirname, oldName);
    const newPath = path.join(__dirname, newName);
    if (fs.existsSync(oldPath)) {
        fs.renameSync(oldPath, newPath);
        console.log(`Renamed: ${oldPath} -> ${newPath}`);
    }
}
