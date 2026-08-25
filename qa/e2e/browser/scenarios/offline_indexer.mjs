import { expect } from '@playwright/test';
import { boot } from '../helpers.mjs';

export async function wasm_offline_indexer(page, fixture) {
  await boot(page);
  const result = await page.evaluate(({ fixture }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const now = String(Date.now());
    const indexer = new sdk.KaspaIndexer(JSON.stringify({ maxTransactions: 123 }));
    indexer.start();
    const addressId = indexer.watchAddress('kaspatest:e2e-address');
    const prefixId = indexer.watchPayloadPrefix(new TextEncoder().encode('portal'));
    const containsId = indexer.watchPayloadContains(new TextEncoder().encode('e2e'));
    const exactId = indexer.watchPayloadExact(new TextEncoder().encode('portal-e2e-payload'));
    const suffixId = indexer.watchPayloadSuffix(new TextEncoder().encode('payload'));
    const genericId = indexer.addMatcher(JSON.stringify({ type: 'payload_contains', value: Array.from(new TextEncoder().encode('remove-me')) }));
    const removed = indexer.removeMatcher(genericId.toString());

    const txA = { ...fixture.indexer.transaction, observed_at_ms: now };
    const firstMatches = JSON.parse(indexer.ingestTransaction(JSON.stringify(txA)));
    const blockA = { hash: 'block-a', daa_score: '10', observed_at_ms: now, txids: ['tx-a'], raw: { hash: 'block-a', daaScore: '10' } };
    indexer.ingestBlock(JSON.stringify(blockA));
    const txB = { txid: 'tx-b', block_hash: 'block-b', daa_score: '11', observed_at_ms: now, addresses: ['kaspatest:e2e-address'], payload: [111,116,104,101,114], raw: { transactionId: 'tx-b', payload: 'other' } };
    const blockB = { hash: 'block-b', daa_score: '11', observed_at_ms: now, txids: ['tx-b'], raw: { hash: 'block-b', daaScore: '11' } };
    const batchReport = JSON.parse(indexer.ingestBlockBatch(JSON.stringify({ block: blockB, transactions: [txB] })));
    const transaction = JSON.parse(indexer.transaction('tx-a'));
    const transactions = JSON.parse(indexer.transactions(JSON.stringify({ address: 'kaspatest:e2e-address', after_daa_score: '9', page: { offset: 0, limit: 10 } })));
    const blocks = JSON.parse(indexer.blocks(JSON.stringify({ offset: 0, limit: 10 })));
    const matches = JSON.parse(indexer.matches(JSON.stringify({ offset: 0, limit: 20 })));
    const metrics = JSON.parse(indexer.metrics());
    const health = JSON.parse(indexer.health());
    const snapshot = indexer.snapshot();
    indexer.clear();
    const clearedTx = JSON.parse(indexer.transaction('tx-a'));
    indexer.restoreSnapshot(snapshot);
    const restoredTx = JSON.parse(indexer.transaction('tx-a'));
    const checkpoint0 = JSON.parse(indexer.checkpoint());
    indexer.setCheckpoint(JSON.stringify({ virtual_daa_score: '11', block_hash: 'block-b' }));
    const checkpoint1 = JSON.parse(indexer.checkpoint());
    const state = indexer.persistedState();
    indexer.clear();
    indexer.restoreState(state);
    const restoredStateTx = JSON.parse(indexer.transaction('tx-a'));
    const syncReport = JSON.parse(indexer.applySyncBatches(
      JSON.stringify([{ block: { hash: 'block-c', daa_score: '12', observed_at_ms: now, txids: [], raw: {} }, transactions: [] }]),
      JSON.stringify({ virtual_daa_score: '12', block_hash: 'block-c' }),
    ));
    const reconcile = JSON.parse(indexer.reconcileVirtualChain(JSON.stringify({
      removed_block_hashes: ['block-c'],
      accepted: [{ block: { hash: 'block-d', daa_score: '13', observed_at_ms: now, txids: [], raw: {} }, transactions: [] }],
      checkpoint: { virtual_daa_score: '13', block_hash: 'block-d' },
    })));
    const events = JSON.parse(indexer.drainEvents());
    indexer.stop();
    const stopped = JSON.parse(indexer.health());
    indexer.clear();
    return {
      ids: [addressId, prefixId, containsId, exactId, suffixId].map(String),
      removed, firstMatches, batchReport, transaction, transactions, blocks, matches, metrics, health,
      clearedTx, restoredTx, checkpoint0, checkpoint1, restoredStateTx, syncReport, reconcile, events, stopped,
    };
  }, { fixture });

  expect(result.ids).toEqual(['1','2','3','4','5']);
  expect(result.removed).toBe(true);
  expect(result.firstMatches).toHaveLength(5);
  expect(result.batchReport.block_hash ?? result.batchReport.blockHash).toBe('block-b');
  expect(result.transaction.txid).toBe('tx-a');
  expect(result.transactions.total).toBe(2);
  expect(result.blocks.total).toBe(2);
  expect(result.matches.total).toBe(6);
  expect(result.metrics.transactions).toBe('2');
  expect(result.metrics.blocks).toBe('2');
  expect(result.metrics.matches).toBe('6');
  expect(result.health.running).toBe(true);
  expect(result.clearedTx).toBeNull();
  expect(result.restoredTx.txid).toBe('tx-a');
  expect(result.checkpoint1.block_hash ?? result.checkpoint1.blockHash).toBe('block-b');
  expect(result.restoredStateTx.txid).toBe('tx-a');
  expect(result.syncReport.blocks_added ?? result.syncReport.blocksAdded).toBe('1');
  expect(result.reconcile.removed_blocks ?? result.reconcile.removedBlocks).toBe(1);
  expect(result.events.length).toBeGreaterThan(0);
  expect(result.stopped.running).toBe(false);
}
