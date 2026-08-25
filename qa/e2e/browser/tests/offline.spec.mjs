import { test } from '@playwright/test';
import { covenantNetwork, readJsonEnv, standardNetwork } from '../helpers.mjs';
import { wasm_offline_portal_network, wasm_offline_wallet } from '../scenarios/offline_portal_wallet.mjs';
import { wasm_offline_transaction } from '../scenarios/offline_transaction.mjs';
import { wasm_offline_contracts } from '../scenarios/offline_contracts.mjs';
import { wasm_offline_privacy } from '../scenarios/offline_privacy.mjs';
import { wasm_offline_indexer } from '../scenarios/offline_indexer.mjs';
import { wasm_offline_randomness } from '../scenarios/offline_randomness.mjs';

let fixture;
test.beforeAll(async () => { fixture = await readJsonEnv('KASPA_PORTAL_E2E_PARITY_FIXTURE'); });

const standard = standardNetwork();
const covenant = covenantNetwork();
test('WASM offline portal/network facade parity', async ({ page }) => wasm_offline_portal_network(page, fixture, standard));
test('WASM offline wallet differential parity', async ({ page }) => wasm_offline_wallet(page, fixture, standard));
test('WASM offline transaction/PSKB differential parity', async ({ page }) => wasm_offline_transaction(page, fixture, standard, covenant));
test('WASM offline contract differential parity', async ({ page }) => wasm_offline_contracts(page, fixture, covenant));
test('WASM offline privacy differential parity', async ({ page }) => wasm_offline_privacy(page, fixture, standard));
test('WASM offline indexer lifecycle', async ({ page }) => wasm_offline_indexer(page, fixture));
test('WASM offline randomness/VRF differential parity', async ({ page }) => wasm_offline_randomness(page, fixture, standard));
