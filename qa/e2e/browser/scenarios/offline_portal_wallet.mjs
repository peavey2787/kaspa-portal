import { expect } from '@playwright/test';
import { boot, bytes } from '../helpers.mjs';

export async function wasm_offline_portal_network(page, fixture, standardNetwork) {
  await boot(page);
  const result = await page.evaluate(({ standardNetwork }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({
      network: standardNetwork,
      endpoint: 'ws://127.0.0.1:17210',
      timeoutMs: '5000',
      maxRetries: 2,
      indexer: { maxTransactions: 123 },
    }));
    const config = JSON.parse(portal.config());
    const network = portal.network();
    const networkId = network.networkId();
    const endpoint = network.endpoint();
    const status = network.status();
    const client = network.client();
    const chain = portal.chain();
    const wallet = portal.wallet();
    const transaction = portal.transaction();
    const contract = portal.contract();
    const privacy = portal.privacy();
    const indexer = portal.indexer();
    const randomness = portal.randomness();
    network.disconnect();
    portal.disconnect();
    return {
      config,
      networkId,
      endpoint,
      status,
      disconnected: network.status(),
      facadeTypes: [client, chain, wallet, transaction, contract, privacy, indexer, randomness]
        .map((value) => value?.constructor?.name || typeof value),
    };
  }, { standardNetwork });
  expect(result.config.network).toBe(standardNetwork.replace('-', ''));
  expect(result.config.timeoutMs).toBe('5000');
  expect(result.config.maxRetries).toBe(2);
  expect(result.config.indexer.max_transactions).toBe(123);
  expect(result.networkId).toBe(standardNetwork.replace('-', ''));
  expect(result.endpoint).toBe('ws://127.0.0.1:17210');
  expect(result.status).toBe('disconnected');
  expect(result.disconnected).toBe('disconnected');
  expect(result.facadeTypes).toHaveLength(8);

  const rejected = await page.evaluate(({ standardNetwork }) => {
    const sdk = globalThis.kaspaPortalSdk;
    try {
      new sdk.KaspaPortal(JSON.stringify({ network: standardNetwork, timeoutMs: '999' }));
      return false;
    } catch {
      return true;
    }
  }, { standardNetwork });
  expect(rejected).toBe(true);
}

export async function wasm_offline_wallet(page, fixture, standardNetwork) {
  await boot(page);
  const rawKpub = bytes(fixture.wallet.rawKpub);
  const result = await page.evaluate(({ fixture, rawKpub, standardNetwork }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network: standardNetwork }));
    const wallet = portal.wallet();
    const imported = JSON.parse(wallet.importKpub(fixture.wallet.kpub));
    const rawImported = JSON.parse(wallet.importKpubRaw(Uint8Array.from(rawKpub)));
    const extended = JSON.parse(wallet.extendAddresses(JSON.stringify(imported), 3, 2));
    const mnemonic12 = JSON.parse(wallet.mnemonic12FromEntropy(new Uint8Array(16).fill(0x11)));
    const mnemonic24 = JSON.parse(wallet.mnemonic24FromEntropy(new Uint8Array(32).fill(0x22)));
    return {
      imported,
      rawImported,
      extended,
      mnemonic12,
      mnemonic24,
      prefix: wallet.prefix(),
    };
  }, { fixture, rawKpub, standardNetwork });

  expect(result.imported).toEqual(fixture.wallet.wallet);
  expect(result.rawImported).toEqual(fixture.wallet.rawWallet);
  expect(result.extended).toEqual(fixture.wallet.extended);
  expect(result.mnemonic12.indices).toEqual(fixture.wallet.mnemonic12.indices);
  expect(result.mnemonic24.indices).toEqual(fixture.wallet.mnemonic24.indices);
  expect(result.prefix).toBe(fixture.wallet.prefix);
}
