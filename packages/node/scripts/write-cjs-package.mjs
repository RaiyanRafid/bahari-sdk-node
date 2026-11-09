// Marks dist/cjs as CommonJS so Node and TypeScript read the .js and .d.ts files there correctly.
import { writeFileSync } from 'node:fs';

writeFileSync(new URL('../dist/cjs/package.json', import.meta.url), JSON.stringify({ type: 'commonjs' }, null, 2) + '\n');
