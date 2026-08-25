import { expect } from '@playwright/test';
import { boot } from '../helpers.mjs';

export async function wasm_live_standard_wallet(page, fixture, config) {
  await boot(page);
  const result = await page.evaluate(async ({ fixture, config }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network: config.network, endpoint: config.endpoint, timeoutMs: '15000', maxRetries: 3 }));
    await portal.connect();
    const walletApi = portal.wallet();
    const walletJson = JSON.stringify(fixture.wallet.wallet);
    const utxos = JSON.parse(await walletApi.utxos(walletJson));
    const balance = JSON.parse(await walletApi.balance(walletJson));
    portal.disconnect();
    return { utxos, balance };
  }, { fixture, config });
  const total = result.utxos.reduce((sum, item) => sum + BigInt(item.amount), 0n);
  expect(BigInt(result.balance.totalSompi)).toBe(total);
  expect(result.balance.utxoCount).toBe(result.utxos.length);
}
