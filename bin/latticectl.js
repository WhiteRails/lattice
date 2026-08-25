#!/usr/bin/env node
'use strict';

// The Node control plane is intentionally named latticectl so it does not
// collide with the native Rust `lattice` client installed beside `latticed`.
require('../dist/cli/lattice.js');
