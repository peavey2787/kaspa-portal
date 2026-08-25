import { expect } from '@playwright/test';
import { addressPrefix, boot, bytes } from '../helpers.mjs';

export async function wasm_offline_transaction(page, fixture, standardNetwork, covenantNetwork) {
  await boot(page);
  const result = await page.evaluate(({ fixture, standardNetwork, covenantNetwork, standardPrefix }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network: standardNetwork }));
    const covenantPortal = new sdk.KaspaPortal(JSON.stringify({ network: covenantNetwork }));
    const transaction = portal.transaction();
    const pskb = transaction.pskb();
    const covenantTransaction = covenantPortal.transaction();
    const covenantPskb = covenantTransaction.pskb();
    const walletJson = JSON.stringify(fixture.wallet.wallet);
    const utxoJson = JSON.stringify([fixture.transaction.utxo]);
    const payload = new TextEncoder().encode('portal-e2e-payload');

    const planned = transaction.planFromUtxos(
      walletJson,
      fixture.transaction.destination,
      '100000000',
      '300000',
      utxoJson,
    );
    const withPayload = transaction.setPayload(planned, payload);
    const lane = transaction.setTxLane(planned, '00'.repeat(20), '7', 1, payload);
    const analysis = JSON.parse(transaction.analyzeWithFeeRate(fixture.transaction.analysisWire, '1'));
    const review = JSON.parse(transaction.review(planned, standardPrefix));

    const encodedDocument = pskb.encodeDocument(JSON.stringify(fixture.transaction.encodeDocumentInput));
    const finalized = JSON.parse(transaction.finalize(fixture.transaction.analysisWire));
    const relay = Uint8Array.from(fixture.transaction.relayKsptHex.match(/../g).map((x) => Number.parseInt(x, 16)));
    const signed = transaction.signCompactKspt(relay, '01'.repeat(32), 1);
    const signedEntropy = transaction.signCompactKsptWithEntropy(relay, '01'.repeat(32), 1, '02'.repeat(32));

    const sequenceProof = fixture.contract.sequenceProof;
    const proofWire = covenantTransaction.applySequenceCommitProof(
      fixture.transaction.covenant.planned,
      sequenceProof.subnetworkId,
      sequenceProof.gas,
      sequenceProof.transactionVersion,
      Uint8Array.from(sequenceProof.payload.match(/../g).map((x) => Number.parseInt(x, 16))),
    );

    const typedPlan = {
      global: {
        txVersion: 0,
        fallbackLockTime: null,
        covenantBranch: null,
        proprietaries: [],
        transactionPayload: null,
      },
      inputs: [{
        utxo: fixture.transaction.utxo,
        sourceScriptPublicKey: fixture.transaction.utxo.script_public_key,
        sequence: '0',
        blockDaaScore: '0',
        sigOpCount: 1,
        minimumSignatures: 1,
        redeemScript: null,
        proprietaries: { typed: true },
        minTime: '0',
      }],
      outputs: [{
        amount: '499000000',
        scriptPublicKey: Array.from(fixture.transaction.destinationScriptHex.match(/../g), (x) => Number.parseInt(x, 16)),
        covenantBindingField: null,
        proprietaries: [],
      }],
    };
    const typedWire = pskb.encode(JSON.stringify(typedPlan));
    const sweep = JSON.parse(pskb.planSweep(
      JSON.stringify([fixture.transaction.utxo]),
      fixture.transaction.sourceScriptHex,
      fixture.transaction.destinationScriptHex,
      '499000000',
      JSON.stringify({
        txVersion: 0,
        fallbackLockTime: '12',
        covenantBranch: 'e2e',
        proprietaries: [],
        transactionPayload: null,
      }),
      JSON.stringify({
        sequence: '0',
        blockDaaScore: '0',
        sigOpCount: 1,
        minimumSignatures: 1,
        redeemScript: null,
        proprietaries: { case: 'e2e' },
        minTime: '0',
      }),
    ));

    const thread = { ...fixture.transaction.covenant.utxo, tx_id: '21'.repeat(32), index: 2, amount: '100000000' };
    const walletTopup = { ...fixture.transaction.covenant.utxo, tx_id: '22'.repeat(32), index: 3, amount: '20000000' };
    const withdrawal = JSON.parse(covenantPskb.planGlobalThreadWithdrawal(
      JSON.stringify([thread]),
      'aabb',
      fixture.transaction.covenant.destinationScriptHex,
      '51ac',
      '42'.repeat(32),
      '20000000',
      '1000000',
      '9',
      JSON.stringify({ withdrawalLockTime: '123', withdrawalBranch: 'beneficiary', topupBranch: 'owner', topupSequence: '0' }),
    ));
    const topup = JSON.parse(covenantPskb.planGlobalThreadTopup(
      JSON.stringify(thread),
      JSON.stringify([walletTopup]),
      'aabb',
      '51ac',
      '42'.repeat(32),
      '1000000',
      JSON.stringify({ withdrawalLockTime: '0', withdrawalBranch: null, topupBranch: null, topupSequence: '11' }),
    ));

    return {
      planned,
      withPayload,
      lane,
      analysis,
      review,
      encodedDocument,
      finalized,
      signed,
      signedEntropy,
      proofWire,
      typedWire,
      sweep,
      withdrawal,
      topup,
    };
  }, { fixture, standardNetwork, covenantNetwork, standardPrefix: addressPrefix(standardNetwork) });

  expect(result.planned).toBe(fixture.transaction.planned);
  expect(result.withPayload).toBe(fixture.transaction.withPayload);
  expect(result.lane).toBe(fixture.transaction.lane);
  expect(result.analysis).toEqual(fixture.transaction.analysis);
  expect(result.review).toEqual(fixture.transaction.review);
  expect(result.encodedDocument).toBe(fixture.transaction.encodedDocument);
  expect(result.finalized).toEqual(fixture.transaction.finalized);
  expect(result.signed).toMatch(/^4b53534e01/);
  expect(result.signedEntropy).toBe(fixture.transaction.signedEntropyKssnHex);
  expect(result.proofWire).not.toBe(result.planned);
  expect(result.typedWire).toMatch(/^50534b42/);
  expect(result.sweep.outputs[0].amount).toBe('499000000');
  expect(result.withdrawal.userReceives).toBe('19000000');
  expect(result.topup.walletTotal).toBe('20000000');
}
