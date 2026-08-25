import { test } from '@playwright/test';
import { readJsonEnv, standardNetworkConfig } from '../helpers.mjs';
import { wasm_live_standard_network_chain } from '../scenarios/live_network_chain.mjs';
import { wasm_live_standard_wallet } from '../scenarios/live_wallet.mjs';
import { wasm_live_standard_transaction_reads } from '../scenarios/live_transaction_reads.mjs';
import { wasm_live_standard_randomness } from '../scenarios/live_randomness.mjs';

let fixture;
test.beforeAll(async () => { fixture = await readJsonEnv('KASPA_PORTAL_E2E_PARITY_FIXTURE'); });

const network = standardNetworkConfig();
test('WASM public standard-network network/chain E2E', async ({ page }) => wasm_live_standard_network_chain(page, fixture, network));
test('WASM public standard-network wallet E2E', async ({ page }) => wasm_live_standard_wallet(page, fixture, network));
test('WASM public standard-network transaction read E2E', async ({ page }) => wasm_live_standard_transaction_reads(page, fixture, network));
test('WASM public standard-network randomness E2E', async ({ page }) => wasm_live_standard_randomness(page, fixture, network));
