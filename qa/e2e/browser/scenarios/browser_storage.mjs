import { expect } from '@playwright/test';
import { boot } from '../helpers.mjs';

export async function wasm_browser_storage_indexeddb(page, fixture, namespace) {
  await boot(page);
  const saved = await page.evaluate(async ({ fixture, namespace }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const indexer = new sdk.KaspaIndexer();
    indexer.start();
    const transaction = { ...fixture.indexer.transaction, observed_at_ms: String(Date.now()) };
    indexer.ingestTransaction(JSON.stringify(transaction));
    await indexer.saveIndexedDb(namespace);
    return JSON.parse(indexer.transaction('tx-a'))?.txid;
  }, { fixture, namespace });
  expect(saved).toBe('tx-a');

  await page.reload();
  await boot(page);
  const restored = await page.evaluate(async ({ namespace }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const indexer = new sdk.KaspaIndexer();
    const loaded = await indexer.loadIndexedDb(namespace);
    const tx = JSON.parse(indexer.transaction('tx-a'));
    await indexer.clearIndexedDb(namespace);
    return { loaded, txid: tx?.txid ?? null };
  }, { namespace });
  expect(restored.loaded).toBe(true);
  expect(restored.txid).toBe('tx-a');

  await page.reload();
  await boot(page);
  const absent = await page.evaluate(async ({ namespace }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const indexer = new sdk.KaspaIndexer();
    return await indexer.loadIndexedDb(namespace);
  }, { namespace });
  expect(absent).toBe(false);
}
