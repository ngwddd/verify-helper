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

export async function restrictPreviewNetwork(context, base, blocked) {
  const origin = new URL(base).origin;
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin === origin) return route.continue();
    blocked.add(url.href);
    return route.abort('blockedbyclient');
  });
  await context.routeWebSocket('**/*', socket => {
    // Static previews have no declared WebSocket service.
    blocked.add(socket.url());
    return socket.close();
  });
}
