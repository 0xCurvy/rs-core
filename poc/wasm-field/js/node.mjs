// Usage: node js/node.mjs WASM_FILE COMMAND...   (prints the JSON result)
import {readFile} from 'node:fs/promises';
import {createRunner} from './harness.mjs';

const [wasmPath, ...command] = process.argv.slice(2);
const runner = await createRunner(await readFile(wasmPath));
const result = runner.run(command.join(' '));
result.engine = `node ${process.version} (V8 ${process.versions.v8})`;
console.log(JSON.stringify(result));
