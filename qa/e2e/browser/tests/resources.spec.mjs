import { test } from '@playwright/test';
import { covenantNetwork, readJsonEnv, standardEndpoint, standardNetwork } from '../helpers.mjs';
import {
  browser_crypto_resources,
  browser_fault_resources,
  browser_indexer_resources,
  browser_network_resources,
  browser_standard_resources,
  browser_storage_resources,
} from '../resource/scenarios.mjs';
import { startFaultServer, stopFaultServer } from '../resource/fault_server.mjs';

let fixture;
let resourceConfig;

test.beforeAll(async () => {
  fixture = await readJsonEnv('KASPA_PORTAL_E2E_PARITY_FIXTURE');
  resourceConfig = await readJsonEnv('KASPA_PORTAL_RESOURCE_PROFILES');
});

test('Chromium standard facade lifecycle stays within resource budgets', async ({ page }) => {
  await browser_standard_resources(page, resourceConfig.profiles.standard, fixture, standardNetwork(), covenantNetwork());
});

test('Chromium indexer lifecycle plateaus and idles', async ({ page }) => {
  await browser_indexer_resources(page, resourceConfig.profiles.indexer);
});

test('Chromium crypto/secret lifecycle plateaus and idles', async ({ page }) => {
  await browser_crypto_resources(page, resourceConfig.profiles.crypto, fixture, standardNetwork());
});

test('Chromium public standard-network connect/reconnect lifecycle releases resources', async ({ page }) => {
  await browser_network_resources(page, resourceConfig.profiles.network, standardNetwork(), standardEndpoint());
});

test('Chromium IndexedDB save/load/clear lifecycle releases handles and backing storage', async ({ page }, testInfo) => {
  await browser_storage_resources(
    page,
    resourceConfig.profiles.browser_storage,
    fixture,
    `kp-resource-${testInfo.project.name}-${Date.now()}`,
  );
});

test('Chromium injected WebSocket failures release resources and return to idle', async ({ page }) => {
  const server = await startFaultServer();
  try {
    await browser_fault_resources(page, resourceConfig.profiles.fault, standardNetwork(), server.endpoint);
  } finally {
    await stopFaultServer(server.child);
  }
});
