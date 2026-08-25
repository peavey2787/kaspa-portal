import { test, expect } from '@playwright/test';
import { boot, readJsonEnv, standardNetwork } from '../helpers.mjs';

let fixture;
test.beforeAll(async () => { fixture = await readJsonEnv('KASPA_PORTAL_E2E_PARITY_FIXTURE'); });

test('WASM initializes and preserves decimal/byte semantics cross-browser', async ({ page }) => {
  await boot(page);
  const result = await page.evaluate(({ fixture, network }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network }));
    const wallet = portal.wallet();
    const imported = JSON.parse(wallet.importKpub(fixture.wallet.kpub));
    const words = JSON.parse(wallet.mnemonic12FromEntropy(new Uint8Array(16).fill(0x11)));
    const contract = portal.contract();
    const dms = contract.dms('11'.repeat(32), '22'.repeat(32), '144');
    const indexer = new sdk.KaspaIndexer();
    const matcher = indexer.watchPayloadExact(new TextEncoder().encode('cross-browser'));
    return {
      prefix: wallet.prefix(),
      receiveCount: imported.receive_addresses.length,
      wordCount: words.words.length,
      dmsLength: dms.length,
      matcher: matcher.toString(),
    };
  }, { fixture, network: standardNetwork() });
  expect(result.prefix).toBe('kaspatest');
  expect(result.receiveCount).toBe(20);
  expect(result.wordCount).toBe(12);
  expect(result.dmsLength).toBeGreaterThan(0);
  expect(result.matcher).toBe('1');
});
