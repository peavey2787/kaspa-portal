import { test } from '@playwright/test';
import { readJsonEnv } from '../helpers.mjs';
import { wasm_browser_storage_indexeddb } from '../scenarios/browser_storage.mjs';

let fixture;
test.beforeAll(async () => { fixture = await readJsonEnv('KASPA_PORTAL_E2E_PARITY_FIXTURE'); });

test('WASM IndexedDB survives reload and clears durably', async ({ page }, testInfo) => {
  const namespace = `kp-e2e-${testInfo.project.name}-${Date.now()}`;
  await wasm_browser_storage_indexeddb(page, fixture, namespace);
});
