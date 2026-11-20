import assert from 'node:assert/strict';
import { test } from 'node:test';
import { arg, flowUrl, screenshotName } from './verification_resources/probe_helpers.mjs';

test('flow entry points retain their deployment prefix', () => {
  const home = 'http://127.0.0.1:5173/project/';
  assert.equal(flowUrl(home, '/en/404.html'), home + 'en/404.html');
  assert.equal(flowUrl(home, ''), home);
  assert.equal(flowUrl(home, 'https://example.invalid/fixture'), 'https://example.invalid/fixture');
});

test('screenshots from different paths retain distinct portable filenames', () => {
  const first = screenshotName('en/index.html');
  assert.match(first, /^[0-9a-f]{64}\.png$/);
  assert.notEqual(first, screenshotName('en_index.html'));
  assert.equal(first, screenshotName('en/index.html'));
});

test('probe arguments retain paths containing spaces and handle missing values', () => {
  const argv = ['--pages', 'folder with spaces/pages.json', '--shots'];
  assert.equal(arg('pages', '', argv), 'folder with spaces/pages.json');
  assert.equal(arg('shots', 'fallback', argv), 'fallback');
});
