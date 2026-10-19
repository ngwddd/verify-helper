#!/usr/bin/env node
/**
 * 浏览器探针 —— 给 verify-helper 的 browser 检查用。
 *
 * 为什么需要它：HTTP 200 只证明文件能取到，证明不了「页面跑起来是对的」。
 * JS 报错、资源 404、点击无反应，只有真把页面跑起来才看得见。
 *
 * 用法：
 *   node browser_probe.mjs --module <含 node_modules/playwright 的目录> \
 *                          --base <http://127.0.0.1:PORT> \
 *                          --pages <pages.json> --out <out.json> [--shots <dir>]
 *
 * pages.json: [{"rel":"index.html","url":"http://127.0.0.1:PORT/index.html"}, ...]
 * 输出 JSON: {ok, pages:[{rel,status,console:[],pageerrors:[],failed:[]}], shots:[]}
 */
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { writeFileSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

function arg(name, fallback = '') {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const moduleDir = arg('module');
const base = arg('base');
const pagesFile = arg('pages');
const outFile = arg('out');
const shotsDir = arg('shots', '');

async function loadPlaywright() {
  // 1) 从指定目录 require（最常见：项目自己的 node_modules）
  // 2) 退回全局解析
  const candidates = [];
  if (moduleDir) {
    try {
      const require = createRequire(join(moduleDir, '__resolver.cjs'));
      candidates.push(() => require('playwright'));
      candidates.push(() => require('playwright-core'));
    } catch { /* ignore */ }
  }
  for (const fn of candidates) {
    try { return fn(); } catch { /* next */ }
  }
  const mod = await import('playwright').catch(() => null);
  if (mod) return mod.default ?? mod;
  throw new Error('找不到 playwright');
}

const { readFileSync } = await import('node:fs');
const pages = JSON.parse(readFileSync(pagesFile, 'utf8'));

let playwright;
try {
  playwright = await loadPlaywright();
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: 'playwright 不可用：' + e.message }));
  process.exit(2);
}

const browser = await playwright.chromium.launch({ headless: true });
const result = { ok: true, pages: [], shots: [] };
if (shotsDir) mkdirSync(shotsDir, { recursive: true });

// 并发跑：串行 20 页要 20 秒，4 路并发约 6 秒。
// 每个页面用独立 context，互不污染。
const CONCURRENCY = Math.max(1, Math.min(6, Number(arg('concurrency', '4')) || 4));

async function visit(p) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await ctx.newPage();
  const rec = { rel: p.rel, status: 0, console: [], pageerrors: [], failed: [] };

  page.on('console', (m) => {
    if (m.type() === 'error' || m.type() === 'warning') {
      rec.console.push({ type: m.type(), text: m.text().slice(0, 300) });
    }
  });
  page.on('pageerror', (e) => {
    rec.pageerrors.push(String(e && e.message ? e.message : e).slice(0, 300));
  });
  page.on('requestfailed', (r) => {
    rec.failed.push({ url: r.url().slice(0, 200), reason: (r.failure()?.errorText || 'failed').slice(0, 120) });
  });
  page.on('response', (r) => {
    if (r.status() >= 400) rec.failed.push({ url: r.url().slice(0, 200), reason: 'HTTP ' + r.status() });
  });

  try {
    const resp = await page.goto(p.url, { waitUntil: 'networkidle', timeout: 15000 });
    rec.status = resp ? resp.status() : 0;
    await page.waitForTimeout(250);      // 让异步渲染里的错误冒出来
    if (shotsDir && result.shots.length < 12) {
      const safe = p.rel.replace(/[\\/:*?"<>|]/g, '_');
      const file = join(shotsDir, safe + '.png');
      await page.screenshot({ path: file, fullPage: false });
      result.shots.push(file);
    }
  } catch (e) {
    rec.error = String(e.message || e).slice(0, 300);
  } finally {
    await ctx.close();
  }
  return rec;
}

const queue = pages.slice();
const workers = Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
  while (queue.length) {
    const p = queue.shift();
    result.pages.push(await visit(p));
  }
});
await Promise.all(workers);

await browser.close();
writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf8');
console.log(JSON.stringify({ ok: result.ok, pages: result.pages.length, shots: result.shots.length }));
