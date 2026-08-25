import { expect } from '@playwright/test';
import { addressPrefix, boot } from '../helpers.mjs';

export async function wasm_offline_contracts(page, fixture, covenantNetwork) {
  await boot(page);
  const result = await page.evaluate(({ fixture, covenantNetwork, covenantPrefix }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network: covenantNetwork }));
    const contract = portal.contract();
    const c = fixture.contract;
    const dms = contract.dms(c.owner, c.second, '144');
    const privateSwap = contract.privateSwap(c.owner, c.second, '000051', '5000', '55'.repeat(16));
    const piggyBank = contract.piggyBank(c.owner, '25000000', '8000', '66'.repeat(8));
    const savings = contract.timelockedSavings(c.owner, c.second, '12345');
    const payjoin = contract.payjoin(c.owner, c.second, '9999', '2', '2');
    const commitReveal = contract.commitReveal(c.owner, '77'.repeat(32), '7777');
    const dmsAddress = contract.p2shAddress(dms, covenantPrefix);
    const csv = contract.csvSequence(dms);
    const cltvPrivate = contract.cltvLocktime(privateSwap);
    const cltvPiggy = contract.cltvLocktime(piggyBank);
    const cltvSavings = contract.cltvLocktime(savings);
    const cltvPayjoin = contract.cltvLocktime(payjoin);
    const cltvCommit = contract.cltvLocktime(commitReveal);
    const noCltv = contract.cltvLocktime(Uint8Array.of(0x51));
    const noCsv = contract.csvSequence(Uint8Array.of(0x51));
    const campaignId = contract.crowdfundCampaignId('100000000', '654321', c.verifyingKeyHash, c.organizerSpk);
    const crowdfundScript = contract.crowdfundRedeemScript(c.owner, '100000000', '654321', c.verifyingKeyHash, c.organizerSpk, '74'.repeat(8));
    const merkleRoot = contract.merkleRoot(JSON.stringify(c.merkleLeaves));
    const merkleProof = JSON.parse(contract.merkleProof(JSON.stringify(c.merkleLeaves), 1));
    const heartbeat = contract.oracleHeartbeatScript();
    const heartbeatSig = contract.oracleHeartbeatSigScript(heartbeat);
    const consumerSig = contract.oracleConsumerSigScript(heartbeat);
    const sequenceProof = JSON.parse(contract.sequenceCommitStealthProof(c.owner, 0x5a));
    const shipping = contract.shippingEscrow(JSON.stringify({
      sellerPubkey: c.owner,
      delivererPubkey: c.second,
      buyerPubkey: c.third,
      arbiterPubkey: c.fourth,
      productSompi: '200000000',
      feeSompi: '1000000',
      cltv1Deadline: '50000',
      cltv2Deadline: '60000',
      salt: '35'.repeat(8),
    }));
    const taggedVault = contract.taggedVault(c.owner);
    const splitVault = contract.splitVault(c.owner);
    const covenantId = contract.covenantId('88'.repeat(32), 3, JSON.stringify([
      { index: 0, amountSompi: '123000000', version: 0, scriptHex: Array.from(taggedVault, (b) => b.toString(16).padStart(2, '0')).join('') },
      { index: 1, amountSompi: '45000000', version: 0, scriptHex: Array.from(splitVault, (b) => b.toString(16).padStart(2, '0')).join('') },
    ]));
    const setup = JSON.parse(contract.zkTrustedSetup());
    const proof = JSON.parse(contract.zkProveCrowdfund(setup.provingKey, JSON.stringify(['10000000','20000000','30000000'])));
    const zkValid = contract.zkVerify(setup.verifyingKey, proof.proof, proof.publicInput);
    return {
      dms: Array.from(dms), privateSwap: Array.from(privateSwap), piggyBank: Array.from(piggyBank),
      savings: Array.from(savings), payjoin: Array.from(payjoin), commitReveal: Array.from(commitReveal),
      dmsAddress, csv, cltvPrivate, cltvPiggy, cltvSavings, cltvPayjoin, cltvCommit, noCltv, noCsv,
      campaignId, crowdfundScript: Array.from(crowdfundScript), merkleRoot, merkleProof,
      heartbeat: Array.from(heartbeat), heartbeatSig: Array.from(heartbeatSig), consumerSig: Array.from(consumerSig),
      sequenceProof, shipping: Array.from(shipping), taggedVault: Array.from(taggedVault), splitVault: Array.from(splitVault),
      covenantId, proofTotal: proof.totalSompi, zkValid,
    };
  }, { fixture, covenantNetwork, covenantPrefix: addressPrefix(covenantNetwork) });
  const hex = (a) => Buffer.from(a).toString('hex');
  expect(hex(result.dms)).toBe(fixture.contract.dms);
  expect(hex(result.privateSwap)).toBe(fixture.contract.privateSwap);
  expect(hex(result.piggyBank)).toBe(fixture.contract.piggyBank);
  expect(hex(result.savings)).toBe(fixture.contract.timelockedSavings);
  expect(hex(result.payjoin)).toBe(fixture.contract.payjoin);
  expect(hex(result.commitReveal)).toBe(fixture.contract.commitReveal);
  expect(result.dmsAddress).toBe(fixture.contract.dmsAddress);
  expect(result.csv).toBe('144');
  expect(result.cltvPrivate).toBe('5000');
  expect(result.cltvPiggy).toBe('8000');
  expect(result.cltvSavings).toBe('12345');
  expect(result.cltvPayjoin).toBe('9999');
  expect(result.cltvCommit).toBe('7777');
  expect(result.noCltv).toBeNull();
  expect(result.noCsv).toBeNull();
  expect(result.campaignId).toBe(fixture.contract.campaignId);
  expect(hex(result.crowdfundScript)).toBe(fixture.contract.crowdfundScript);
  expect(result.merkleRoot).toBe(fixture.contract.merkleRoot);
  expect(result.merkleProof).toEqual(fixture.contract.merkleProof);
  expect(hex(result.heartbeat)).toBe(fixture.contract.heartbeat);
  expect(hex(result.heartbeatSig)).toBe(fixture.contract.heartbeatSig);
  expect(hex(result.consumerSig)).toBe(fixture.contract.consumerSig);
  expect(result.sequenceProof).toEqual(fixture.contract.sequenceProof);
  expect(hex(result.shipping)).toBe(fixture.contract.shipping);
  expect(hex(result.taggedVault)).toBe(fixture.contract.taggedVault);
  expect(hex(result.splitVault)).toBe(fixture.contract.splitVault);
  expect(result.covenantId).toBe(fixture.contract.covenantId);
  expect(result.proofTotal).toBe('60000000');
  expect(result.zkValid).toBe(true);
}
