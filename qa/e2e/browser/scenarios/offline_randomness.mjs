import { expect } from '@playwright/test';
import { boot } from '../helpers.mjs';

export async function wasm_offline_randomness(page, fixture, network) {
  await boot(page);
  const result = await page.evaluate(({ fixture, network }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network }));
    const fromPortal = portal.randomness();
    const direct = new sdk.KaspaRandomness();
    const request = fixture.randomness.beaconRequest;
    direct.observeKaspaBlock(JSON.stringify(request.kaspa[0]));
    const beacon = JSON.parse(direct.generateBeacon(JSON.stringify(request)));
    const verification = JSON.parse(direct.verifyBeacon(JSON.stringify(beacon)));

    const input = Uint8Array.from(fixture.randomness.vrfInput.match(/../g).map((x) => Number.parseInt(x, 16)));
    const fixed = new sdk.KaspaVrfSecretKey(fixture.randomness.vrfSecret);
    const fixedPublic = fixed.publicKey();
    const exposed = fixed.exposeSecret();
    const fixedResult = JSON.parse(fixed.prove(input));
    const apiPublic = fromPortal.vrfPublicKey(fixture.randomness.vrfSecret);
    const apiResult = JSON.parse(fromPortal.vrfProve(fixture.randomness.vrfSecret, input));
    const proofHex = Array.from(apiResult.proof, (b) => b.toString(16).padStart(2, '0')).join('');
    const verified = fromPortal.vrfVerify(apiPublic, input, proofHex);

    const generated = fromPortal.generateVrfKeypair();
    const generatedPublic = generated.publicKey();
    const generatedResult = JSON.parse(generated.prove(new TextEncoder().encode('generated-key-e2e')));
    const generatedProofHex = Array.from(generatedResult.proof, (b) => b.toString(16).padStart(2, '0')).join('');
    const generatedVerified = fromPortal.vrfVerify(generatedPublic, new TextEncoder().encode('generated-key-e2e'), generatedProofHex);
    generated.free();
    fixed.free();
    return {
      portalType: fromPortal.constructor.name,
      beacon,
      verification,
      fixedPublic,
      exposed,
      fixedResult,
      apiPublic,
      apiResult,
      verified,
      generatedPublic,
      generatedResult,
      generatedVerified,
    };
  }, { fixture, network });

  expect(result.beacon).toEqual(fixture.randomness.beacon);
  expect(result.verification).toEqual(fixture.randomness.beaconVerification);
  expect(result.fixedPublic).toBe(fixture.randomness.vrfPublic);
  expect(result.exposed).toBe(fixture.randomness.vrfSecret);
  expect(result.fixedResult).toEqual(fixture.randomness.vrfResult);
  expect(result.apiPublic).toBe(fixture.randomness.vrfPublic);
  expect(result.apiResult).toEqual(fixture.randomness.vrfResult);
  const expectedOutputHex = Buffer.from(fixture.randomness.vrfResult.output).toString('hex');
  expect(result.verified).toBe(expectedOutputHex);
  expect(result.generatedPublic).toHaveLength(64);
  expect(result.generatedResult.proof).toHaveLength(80);
  expect(result.generatedVerified).toBe(Buffer.from(result.generatedResult.output).toString('hex'));
}
