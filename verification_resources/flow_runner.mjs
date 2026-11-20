#!/usr/bin/env node
/**
 * 交互流程执行器 —— 给 verify-helper 的 interaction 检查用。
 *
 * 干的事：按 verify.toml 里写的步骤，真的去点、去填、去选，然后断言结果。
 * 页面「能打开」和「点了有反应」是两件事，这一层只管后者。
 *
 * 用法：
 *   node flow_runner.mjs --module <含 playwright 的目录> --spec <spec.json> --out <out.json> [--shots <dir>]
 *
 * spec.json:
 *   {
 *     "base": "http://127.0.0.1:1234",
 *     "timeoutMs": 10000,
 *     "flows": [ { "name": "...", "steps": [ {"goto": "..."}, {"click": "..."}, {"expect": {...}} ] } ]
 *   }
 *
 * 输出：每条流程的结果、失败在哪一步、当时的 console 错误、失败截图路径。
 */
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { arg, flowUrl, screenshotName } from './probe_helpers.mjs';

const moduleDir = arg('module');
const specFile = arg('spec');
const outFile = arg('out');
const shotsDir = arg('shots', '');

async function loadPlaywright() {
  if (moduleDir) {
    try {
      const require = createRequire(join(moduleDir, '__resolver.cjs'));
      try { return require('playwright'); } catch { /* next */ }
      try { return require('playwright-core'); } catch { /* next */ }
    } catch { /* ignore */ }
  }
  const mod = await import('playwright').catch(() => null);
  if (mod) return mod.default ?? mod;
  throw new Error('找不到 playwright');
}

const spec = JSON.parse(readFileSync(specFile, 'utf8'));
const STEP_TIMEOUT = spec.timeoutMs || 10000;
const EXPECT_TIMEOUT = Math.min(STEP_TIMEOUT, 5000);

let playwright;
try {
  playwright = await loadPlaywright();
} catch (e) {
  console.log(JSON.stringify({ ok: false, error: 'playwright 不可用：' + e.message }));
  process.exit(2);
}

if (shotsDir) mkdirSync(shotsDir, { recursive: true });

const browser = await playwright.chromium.launch({ headless: true });
const results = [];

function describe(step) {
  if (step.goto !== undefined) return `打开 ${step.goto}`;
  if (step.click !== undefined) return `点击 ${step.click}`;
  if (step.fill !== undefined) return `填写 ${step.fill}`;
  if (step.select !== undefined) return `选择 ${step.select}`;
  if (step.press !== undefined) return `按键 ${step.press}`;
  if (step.wait !== undefined) return `等待 ${step.wait}ms`;
  if (step.expect !== undefined) return `断言 ${JSON.stringify(step.expect)}`;
  return JSON.stringify(step);
}

/** 轮询直到 cond 为真或超时；返回 {ok, detail} */
async function until(fn, timeout, what) {
  const deadline = Date.now() + timeout;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const r = await fn();
      if (r === true) return { ok: true, detail: '' };
      if (typeof r === 'string') last = r;
    } catch (e) {
      last = String(e.message || e).slice(0, 200);
    }
    await new Promise((r) => setTimeout(r, 120));
  }
  return { ok: false, detail: last || `${what} 在 ${timeout}ms 内未满足` };
}

async function runExpect(page, expect, consoleErrors) {
  const timeout = expect.timeout || EXPECT_TIMEOUT;
  const selector = expect.selector;

  return until(async () => {
    if (expect.no_console_error && consoleErrors.length) {
      return 'Console reported an error';
    }
    if (expect.url_contains && !page.url().includes(expect.url_contains)) {
      return 'URL did not match';
    }
    if (!selector) return true;

    const element = page.locator(selector).first();
    if (expect.input_value !== undefined &&
        await element.inputValue({ timeout: 1000 }) !== String(expect.input_value)) {
      return 'Input value did not match';
    }
    if (expect.text_contains !== undefined &&
        !(await element.textContent({ timeout: 1000 }) || '').includes(expect.text_contains)) {
      return 'Text did not match';
    }
    const visible = expect.visible ?? (expect.input_value === undefined && expect.text_contains === undefined);
    if ((expect.visible !== undefined || visible) && await element.isVisible() !== visible) {
      return 'Element visibility did not match';
    }
    return true;
  }, timeout, 'Combined browser assertion');
}

for (const flow of spec.flows || []) {
  const name = flow.name || '(未命名流程)';
  const rec = { name, passed: false, failedStep: null, error: null, console: [], shot: null };
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const consoleErrors = [];
  const pageErrors = [];

  page.on('console', (m) => {
    if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 240));
  });
  page.on('pageerror', (e) => pageErrors.push(String(e.message || e).slice(0, 240)));

  try {
    for (let i = 0; i < (flow.steps || []).length; i++) {
      const step = flow.steps[i];
      const where = { index: i + 1, action: describe(step) };
      let outcome = { ok: true, detail: '' };
      try {
        if (step.goto !== undefined) {
          const r = await page.goto(flowUrl(spec.base, step.goto),
                                    { waitUntil: 'networkidle', timeout: STEP_TIMEOUT });
          if (r && r.status() >= 400) outcome = { ok: false, detail: `HTTP ${r.status()}` };
        } else if (step.click !== undefined) {
          await page.click(step.click, { timeout: STEP_TIMEOUT });
        } else if (step.fill !== undefined) {
          await page.fill(step.fill, String(step.value ?? ''), { timeout: STEP_TIMEOUT });
        } else if (step.select !== undefined) {
          await page.selectOption(step.select, String(step.value ?? ''), { timeout: STEP_TIMEOUT });
        } else if (step.press !== undefined) {
          if (step.selector) await page.press(step.selector, step.press, { timeout: STEP_TIMEOUT });
          else await page.keyboard.press(step.press);
        } else if (step.wait !== undefined) {
          await page.waitForTimeout(Number(step.wait) || 0);
        } else if (step.expect !== undefined) {
          outcome = await runExpect(page, step.expect, consoleErrors);
        } else {
          outcome = { ok: false, detail: '这一步无法识别：' + JSON.stringify(step).slice(0, 120) };
        }
      } catch (e) {
        outcome = { ok: false, detail: String(e.message || e).slice(0, 240) };
      }

      if (!outcome.ok) {
        rec.failedStep = { ...where, detail: outcome.detail };
        break;
      }
    }
    rec.passed = rec.failedStep === null;
    // 未捕获异常一律算失败：点了按钮抛出异常，即使断言碰巧通过也是 bug。
    // console.error 不主动判失败，需要时在流程里写 { expect: { no_console_error: true } }。
    if (rec.passed && pageErrors.length) {
      rec.passed = false;
      rec.failedStep = {
        index: -1,
        action: '(流程执行期间)',
        detail: `出现未捕获异常：${pageErrors[0]}`,
      };
    }
  } catch (e) {
    rec.error = String(e.message || e).slice(0, 240);
  } finally {
    rec.console = consoleErrors.slice(0, 8);
    rec.pageErrors = pageErrors.slice(0, 8);
    if (!rec.passed && shotsDir) {
      try {
        const file = join(shotsDir, screenshotName(`${results.length + 1}:${name}`));
        await page.screenshot({ path: file, fullPage: false });
        rec.shot = file;
      } catch { /* 截图失败不影响结论 */ }
    }
    await ctx.close();
  }

  results.push(rec);
}

await browser.close();
writeFileSync(outFile, JSON.stringify({ ok: true, flows: results }, null, 2), 'utf8');
console.log(JSON.stringify({
  ok: true,
  total: results.length,
  passed: results.filter((r) => r.passed).length,
}));
