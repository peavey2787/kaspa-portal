import { expect } from '@playwright/test';
import { boot } from '../helpers.mjs';

export async function wasm_funded_standard_network_transactions(page, funded) {
  await boot(page);
  const result = await page.evaluate(async ({ funded }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({
      network: funded.network, endpoint: funded.endpoint, timeoutMs: '15000', maxRetries: 3,
    }));
    await portal.connect();
    const transaction = portal.transaction();
    const walletJson = JSON.stringify(funded.wallet);
    const fee = funded.feeSompi;

    const planned = await transaction.planSend(walletJson, funded.destination, '20000000', fee);
    const payloadPlan = await transaction.planSendWithPayload(
      walletJson, funded.destination, '20000000', fee, new TextEncoder().encode('browser-plan-payload'),
    );
    const selected = await transaction.planSelectedSend(walletJson, funded.destination, '10000000', fee, '[0]');
    if (typeof payloadPlan !== 'string') throw new Error('planSendWithPayload did not return a PSKB wire');
    const analysis = JSON.parse(await transaction.analyze(funded.signedBroadcastWire));

    const txid = await transaction.broadcast(funded.signedBroadcastWire);
    let observed = false;
    for (let i = 0; i < 90; i += 1) {
      const entries = JSON.parse(await portal.chain().utxos(funded.destination));
      if (entries.some((entry) => entry.tx_id === txid)) { observed = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    let duplicateRejected = false;
    try {
      await transaction.broadcastWire(funded.signedBroadcastWire);
    } catch {
      duplicateRejected = true;
    }

    const consolidation = await transaction.planConsolidation(walletJson, fee);
    const multisig = await transaction.planMultisigConsolidation(
      funded.multisig.descriptor,
      funded.multisig.sourcesJson,
      funded.wallet.receive_addresses[2],
      funded.multisig.amountSompi,
      fee,
      0,
      0,
    );
    const reviews = [planned, selected, consolidation, multisig]
      .map((wire) => JSON.parse(transaction.review(wire, funded.addressPrefix)));
    portal.disconnect();
    return { txid, observed, duplicateRejected, analysis, reviews };
  }, { funded });

  expect(result.txid).toHaveLength(64);
  expect(result.observed).toBe(true);
  expect(result.duplicateRejected).toBe(true);
  expect(result.analysis.mass_valid ?? result.analysis.massValid).toBe(true);
  expect(result.analysis.fee_sufficient ?? result.analysis.feeSufficient).toBe(true);
  expect(result.reviews).toHaveLength(4);
  for (const review of result.reviews) expect(review.input_count ?? review.inputCount).toBeGreaterThan(0);
}

export async function wasm_funded_covenant_network_transactions(page, funded) {
  await boot(page);
  const result = await page.evaluate(async ({ funded }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({
      network: funded.network, endpoint: funded.endpoint, timeoutMs: '15000', maxRetries: 3,
    }));
    await portal.connect();
    const transaction = portal.transaction();
    const walletJson = JSON.stringify(funded.wallet);
    const covenant = await transaction.planCovenant(
      walletJson,
      funded.address,
      '50000000',
      funded.feeSompi,
      funded.changeAddress,
      '',
      'payload',
      '706f7274616c2d7761736d2d653265',
      false,
    );
    const bound = JSON.parse(await transaction.planCovenantWithBinding(
      walletJson,
      funded.address,
      '50000000',
      funded.feeSompi,
      funded.changeAddress,
      '',
      'payload',
      '706f7274616c2d7761736d2d626f756e64',
      true,
    ));
    const reviews = [covenant, bound.wire]
      .map((wire) => JSON.parse(transaction.review(wire, funded.addressPrefix)));
    portal.disconnect();
    return { reviews, bound };
  }, { funded });

  expect(result.reviews).toHaveLength(2);
  for (const review of result.reviews) expect(review.input_count ?? review.inputCount).toBeGreaterThan(0);
  expect(result.bound.covenantId).toHaveLength(64);
}
