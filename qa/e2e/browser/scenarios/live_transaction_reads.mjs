import { expect } from '@playwright/test';
import { boot } from '../helpers.mjs';

export async function wasm_live_standard_transaction_reads(page, fixture, config) {
  await boot(page);
  const result = await page.evaluate(async ({ fixture, config }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network: config.network, endpoint: config.endpoint, timeoutMs: '15000', maxRetries: 3 }));
    await portal.connect();
    const descriptor = `multi_hd45(2,${fixture.wallet.multisigKpub1},${fixture.wallet.multisigKpub2})`;
    const scanned = JSON.parse(await portal.transaction().scanMultisigBranch(descriptor, 0, 2, config.addressPrefix));
    portal.disconnect();
    return { descriptor, scanned };
  }, { fixture, config });
  expect(result.descriptor).toContain('multi_hd45');
  expect(result.scanned.cosigner_index).toBe(0);
  expect(result.scanned.depth).toBe(2);
  expect(Array.isArray(result.scanned.utxos)).toBe(true);
  expect(result.scanned.utxo_count).toBe(result.scanned.utxos.length);
  expect(typeof result.scanned.balance_sompi).toBe('string');
  expect(/^\d+$/.test(result.scanned.balance_sompi)).toBe(true);
  expect(result.scanned.next_receive_index).toBeGreaterThanOrEqual(0);
  expect(result.scanned.next_receive_index).toBeLessThanOrEqual(2);
  expect(result.scanned.next_change_index).toBeGreaterThanOrEqual(0);
  expect(result.scanned.next_change_index).toBeLessThanOrEqual(2);
  let summedBalance = 0n;
  for (const utxo of result.scanned.utxos) {
    expect(utxo.address.startsWith(`${config.addressPrefix}:`)).toBe(true);
    expect(utxo.chain === 0 || utxo.chain === 1).toBe(true);
    expect(utxo.index).toBeGreaterThanOrEqual(0);
    expect(utxo.index).toBeLessThan(2);
    expect(typeof utxo.amount).toBe('string');
    expect(/^\d+$/.test(utxo.amount)).toBe(true);
    summedBalance += BigInt(utxo.amount);
  }
  expect(summedBalance).toBe(BigInt(result.scanned.balance_sompi));
}
