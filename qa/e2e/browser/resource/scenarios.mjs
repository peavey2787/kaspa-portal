import { addressPrefix, boot } from '../helpers.mjs';
import { measureProfile } from './metrics.mjs';


export async function browser_standard_resources(page, profile, fixture, standardNetwork, covenantNetwork) {
  await boot(page);
  return measureProfile(page, profile, async () => {
    await page.evaluate(({ kpub, standardNetwork, covenantNetwork, standardPrefix }) => {
      const sdk = globalThis.kaspaPortalSdk;
      const portal = new sdk.KaspaPortal(JSON.stringify({ network: standardNetwork, endpoint: 'ws://127.0.0.1:1' }));
      const covenantPortal = new sdk.KaspaPortal(JSON.stringify({ network: covenantNetwork }));
      const network = portal.network();
      const wallet = portal.wallet();
      const transaction = portal.transaction();
      const contract = covenantPortal.contract();
      const privacy = portal.privacy();
      const indexer = portal.indexer();
      const randomness = portal.randomness();
      portal.config();
      network.status();
      wallet.importKpub(kpub);
      wallet.prefix();
      const pskb = transaction.pskb();
      contract.dms('11'.repeat(32), '22'.repeat(32), '144');
      privacy.announcementAddress(standardPrefix);
      indexer.health();
      freeLocal(pskb, network, wallet, transaction, contract, privacy, indexer, randomness, covenantPortal, portal);
      function freeLocal(...items) { for (const item of items) if (item && typeof item.free === 'function') item.free(); }
    }, {
      kpub: fixture.wallet.kpub,
      standardNetwork,
      covenantNetwork,
      standardPrefix: addressPrefix(standardNetwork),
    });
  }, 'browser-standard');
}

export async function browser_indexer_resources(page, profile) {
  await boot(page);
  return measureProfile(page, profile, async (iteration) => {
    await page.evaluate(({ iteration }) => {
      const sdk = globalThis.kaspaPortalSdk;
      const indexer = new sdk.KaspaIndexer();
      indexer.start();
      indexer.watchPayloadContains(new TextEncoder().encode('resource'));
      for (let item = 0; item < 16; item += 1) {
        indexer.ingestTransaction(JSON.stringify({
          txid: `resource-${iteration}-${item}`,
          block_hash: null,
          daa_score: String(item),
          observed_at_ms: String(Date.now()),
          addresses: ['kaspatest:resource'],
          payload: Array.from(new TextEncoder().encode(`resource-${item}`)),
          raw: { iteration, item },
        }));
      }
      const snapshot = indexer.snapshot();
      indexer.metrics();
      indexer.clear();
      indexer.restoreSnapshot(snapshot);
      indexer.drainEvents();
      indexer.stop();
      indexer.clear();
      if (typeof indexer.free === 'function') indexer.free();
    }, { iteration });
  }, 'browser-indexer');
}

export async function browser_crypto_resources(page, profile, fixture, standardNetwork) {
  await boot(page);
  return measureProfile(page, profile, async (iteration) => {
    await page.evaluate(({ iteration, kpub, vrfSecret, standardNetwork }) => {
      const sdk = globalThis.kaspaPortalSdk;
      const portal = new sdk.KaspaPortal(JSON.stringify({ network: standardNetwork }));
      const randomness = portal.randomness();
      const secret = new sdk.KaspaVrfSecretKey(vrfSecret);
      const input = new TextEncoder().encode(`resource-vrf-${iteration}`);
      const proof = JSON.parse(secret.prove(input));
      const proofHex = Array.from(proof.proof, (byte) => byte.toString(16).padStart(2, '0')).join('');
      randomness.vrfVerify(secret.publicKey(), input, proofHex);
      const privacy = portal.privacy();
      const metadata = privacy.deriveMetadata(kpub);
      privacy.generateStealthPayment(metadata, '53'.repeat(32));
      freeLocal(secret, privacy, randomness, portal);
      function freeLocal(...items) { for (const item of items) if (item && typeof item.free === 'function') item.free(); }
    }, { iteration, kpub: fixture.wallet.kpub, vrfSecret: fixture.randomness.vrfSecret, standardNetwork });
  }, 'browser-crypto');
}

export async function browser_network_resources(page, profile, networkName, endpoint) {
  await boot(page);
  return measureProfile(page, profile, async () => {
    await page.evaluate(async ({ networkName, endpoint }) => {
      const sdk = globalThis.kaspaPortalSdk;
      const portal = new sdk.KaspaPortal(JSON.stringify({ network: networkName, endpoint, timeoutMs: '15000', maxRetries: 3 }));
      const network = portal.network();
      await network.connect();
      await network.health();
      await network.reconnect();
      network.disconnect();
      portal.disconnect();
      freeLocal(network, portal);
      function freeLocal(...items) { for (const item of items) if (item && typeof item.free === 'function') item.free(); }
    }, { networkName, endpoint });
  }, 'browser-network');
}

export async function browser_storage_resources(page, profile, fixture, namespacePrefix) {
  await boot(page);
  return measureProfile(page, profile, async (iteration) => {
    await page.evaluate(async ({ fixture, namespace }) => {
      const sdk = globalThis.kaspaPortalSdk;
      const indexer = new sdk.KaspaIndexer();
      indexer.start();
      const transaction = { ...fixture.indexer.transaction, observed_at_ms: String(Date.now()) };
      indexer.ingestTransaction(JSON.stringify(transaction));
      await indexer.saveIndexedDb(namespace);
      indexer.clear();
      await indexer.loadIndexedDb(namespace);
      await indexer.clearIndexedDb(namespace);
      indexer.stop();
      indexer.clear();
      if (typeof indexer.free === 'function') indexer.free();
    }, { fixture, namespace: `${namespacePrefix}-${iteration}` });
  }, 'browser-storage');
}

export async function browser_fault_resources(page, profile, networkName, endpoint) {
  await boot(page);
  return measureProfile(page, profile, async (iteration) => {
    await page.evaluate(async ({ networkName, endpoint, mode }) => {
      const sdk = globalThis.kaspaPortalSdk;
      async function invoke(selectedMode) {
        const portal = new sdk.KaspaPortal(JSON.stringify({
          network: networkName,
          endpoint,
          timeoutMs: '15000',
          maxRetries: 0,
        }));
        const network = portal.network();
        const client = network.client();
        try {
          return await client.call(131, Uint8Array.of(selectedMode));
        } catch (_error) {
          return null;
        } finally {
          if (typeof client.free === 'function') client.free();
          if (typeof network.free === 'function') network.free();
          if (typeof portal.free === 'function') portal.free();
        }
      }
      const failed = await invoke(mode);
      if (failed !== null) throw new Error(`fault mode ${mode} unexpectedly succeeded`);
      const recovered = await invoke(0);
      if (new TextDecoder().decode(recovered) !== 'fault-ok') {
        throw new Error('fault transport recovery returned unexpected payload');
      }
    }, { networkName, endpoint, mode: 3 + (iteration % 6) });
  }, 'browser-fault');
}
