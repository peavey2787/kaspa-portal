import { expect } from '@playwright/test';
import { boot } from '../helpers.mjs';

export async function wasm_live_standard_randomness(page, fixture, config) {
  await boot(page);
  const result = await page.evaluate(async ({ config }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network: config.network, endpoint: config.endpoint, timeoutMs: '15000', maxRetries: 3 }));
    await portal.connect();
    const raw = await portal.chain().blockRaw(config.genesisHash);
    const randomness = portal.randomness();
    randomness.observeKaspaBlock(JSON.stringify({
      block_hash: Array.from(config.genesisHash.match(/../g), (x) => Number.parseInt(x, 16)),
      daa_score: null,
      finalized: true,
    }));
    const context = new TextEncoder().encode(`kaspa-portal-live-${config.network}`);
    const generated = JSON.parse(await randomness.generateLive(config.network, 1, false, context));
    const verified = JSON.parse(randomness.verifyBeacon(JSON.stringify(generated)));
    portal.disconnect();
    return { rawLength: raw.length, generated, verified };
  }, { config });
  expect(result.rawLength).toBeGreaterThan(0);
  expect(result.generated.output).toHaveLength(32);
  expect(result.verified.valid).toBe(true);
  expect(result.verified.kaspa_evidence_finalized ?? result.verified.kaspaEvidenceFinalized).toBe(true);
}
