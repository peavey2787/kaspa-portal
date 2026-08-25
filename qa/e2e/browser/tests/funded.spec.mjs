import { test } from '@playwright/test';
import { readJsonEnv } from '../helpers.mjs';
import {
  wasm_funded_covenant_network_transactions,
  wasm_funded_standard_network_transactions,
} from '../scenarios/funded_transactions.mjs';

const skipStandard = process.env.KASPA_PORTAL_E2E_SKIP_STANDARD_FUNDED === '1';
const skipCovenant = process.env.KASPA_PORTAL_E2E_SKIP_COVENANT_FUNDED === '1';
let funded;
test.beforeAll(async () => {
  if (!skipStandard || !skipCovenant) funded = await readJsonEnv('KASPA_PORTAL_E2E_FUNDED_FIXTURE');
});

test('WASM funded standard-network transaction E2E', async ({ page }) => {
  test.skip(skipStandard, 'standard-network funded E2E explicitly skipped');
  await wasm_funded_standard_network_transactions(page, funded.standard);
});

test('WASM funded covenant-network transaction E2E', async ({ page }) => {
  test.skip(skipCovenant, 'covenant-network funded E2E explicitly skipped');
  await wasm_funded_covenant_network_transactions(page, funded.covenant);
});
