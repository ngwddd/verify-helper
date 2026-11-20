import { createHash } from 'node:crypto';

export function arg(name, fallback = '', argv = process.argv.slice(2)) {
  const index = argv.indexOf('--' + name);
  return index >= 0 ? (argv[index + 1] ?? fallback) : fallback;
}

export function flowUrl(base, path) {
  if (/^https?:/i.test(path)) return path;
  return base.replace(/\/$/, '') + '/' + String(path || '').replace(/^\//, '');
}

export function screenshotName(subject) {
  return createHash('sha256').update(subject).digest('hex') + '.png';
}
