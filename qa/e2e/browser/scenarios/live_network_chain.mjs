import { expect } from '@playwright/test';
import { boot, INDEXED_FIXTURE_TXID } from '../helpers.mjs';

export async function wasm_live_standard_network_chain(page, fixture, config) {
  await boot(page);
  const result = await page.evaluate(async ({ fixture, config, indexedTxid }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portalConfig = { network: config.network, endpoint: config.endpoint, timeoutMs: '15000', maxRetries: 3 };
    const builderConnected = new sdk.KaspaPortal(JSON.stringify(portalConfig));
    const builderHealth = JSON.parse(await builderConnected.connect());
    builderConnected.disconnect();

    const portal = new sdk.KaspaPortal(JSON.stringify(portalConfig));
    const portalHealth = JSON.parse(await portal.connect());
    const network = portal.network();
    const direct = JSON.parse(await network.connect());
    const health = JSON.parse(await network.health());
    const reconnected = JSON.parse(await network.reconnect());
    const raw = await network.client().call(131, Uint8Array.from([1, 0]));
    const chain = portal.chain();
    const daa = await chain.virtualDaaScore();
    const genesis = await chain.blockRaw(config.genesisHash);
    const address = fixture.wallet.wallet.receive_addresses[0];
    const single = JSON.parse(await chain.utxos(address));
    const many = JSON.parse(await chain.utxosMany(JSON.stringify(fixture.wallet.wallet.receive_addresses.slice(0, 2))));
    const fee = JSON.parse(await chain.feeEstimate());

    const indexedPayload = new TextEncoder().encode('standard-network-indexed-payload');
    portal.indexer().ingestTransaction(JSON.stringify({
      txid: indexedTxid,
      block_hash: null,
      daa_score: daa.toString(),
      observed_at_ms: String(Date.now()),
      addresses: [address],
      payload: Array.from(indexedPayload),
      raw: { version: 1, inputs: [], outputs: [], lockTime: '0', subnetworkId: '00'.repeat(20), gas: '0', payload: Array.from(indexedPayload, (b) => b.toString(16).padStart(2, '0')).join('') },
    }));
    const transaction = JSON.parse(chain.transaction(indexedTxid));
    const transactionRaw = JSON.parse(chain.transactionRaw(indexedTxid));
    portal.disconnect();
    return {
      builderHealth, portalHealth, direct, health, reconnected,
      rawLength: raw.length, daa: daa.toString(), genesisLength: genesis.length,
      singleCount: single.length, manyCount: many.length, fee, transaction, transactionRaw,
      statusAfterDisconnect: network.status(),
    };
  }, { fixture, config, indexedTxid: INDEXED_FIXTURE_TXID });

  expect(result.builderHealth.status).toBe('connected');
  expect(result.portalHealth.status).toBe('connected');
  expect(result.direct.status).toBe('connected');
  expect(result.health.status).toBe('connected');
  expect(result.reconnected.status).toBe('connected');
  expect(result.rawLength).toBeGreaterThan(0);
  expect(BigInt(result.daa)).toBeGreaterThan(0n);
  expect(result.genesisLength).toBeGreaterThan(0);
  expect(result.manyCount).toBeGreaterThanOrEqual(result.singleCount);
  expect(Number(result.fee.normal_sompi_per_gram ?? result.fee.normalSompiPerGram)).toBeGreaterThanOrEqual(0);
  expect(result.transaction.txid).toBe(INDEXED_FIXTURE_TXID);
  expect(result.transactionRaw.version).toBe(1);
  expect(result.statusAfterDisconnect).toBe('disconnected');
}
