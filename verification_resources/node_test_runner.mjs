import { readFileSync } from 'node:fs';
import { extname, resolve } from 'node:path';
import { run } from 'node:test';

const names = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const typeScript = new Set(['.ts', '.mts', '.cts']);
const files = new Map(names
  .filter(name => process.features.typescript || !typeScript.has(extname(name.toLowerCase())))
  .map(name => [resolve(name), name]));
const completed = new Set();
const findings = [];
let summary;

if (files.size) {
  for await (const { type, data } of run({ files: [...files.keys()], concurrency: true })) {
    if (type === 'test:complete' && data.nesting === 0 &&
        data.name === data.file && !data.entryFile && files.has(data.file)) {
      completed.add(files.get(data.file));
    } else if (type === 'test:summary' && data.file === undefined) {
      summary = data;
    } else if (type === 'test:fail' && !data.todo && !data.skip && findings.length < 100 &&
               files.has(data.file) && Number.isSafeInteger(data.line)) {
      findings.push([files.get(data.file), data.line]);
      console.error(data.details?.error?.stack ?? 'Node test failed');
    } else if (type === 'test:stderr' || type === 'test:stdout') {
      process.stderr.write(data.message);
    }
  }
}

console.log('\nVH_NODE_TEST ' + JSON.stringify({
  version: process.versions.node,
  completed: [...completed],
  findings,
  summary: summary ? { success: summary.success, counts: summary.counts } : null,
}));
process.exitCode = summary === undefined ? 2 : summary.success ? 0 : 1;
