import { expect } from '@playwright/test';
import { addressPrefix, boot } from '../helpers.mjs';

export async function wasm_offline_privacy(page, fixture, network) {
  await boot(page);
  const result = await page.evaluate(({ fixture, network, prefix }) => {
    const sdk = globalThis.kaspaPortalSdk;
    const portal = new sdk.KaspaPortal(JSON.stringify({ network }));
    const privacy = portal.privacy();
    const encoded = privacy.deriveMetadata(fixture.privacy.kpub);
    const decoded = JSON.parse(privacy.decodeMetadata(encoded));
    const reencoded = privacy.encodeMetadata(JSON.stringify(decoded));
    const payment = JSON.parse(privacy.generateStealthPayment(encoded, '53'.repeat(32)));
    const announcement = privacy.announcementAddress(prefix);
    const raw = Uint8Array.from(fixture.privacy.scannerRaw.match(/../g).map((x) => Number.parseInt(x, 16)));
    const found = privacy.scanRawForPreimage(raw, fixture.privacy.scannerTxid);
    const missing = privacy.scanRawForPreimage(raw, '62'.repeat(32));
    return { encoded, decoded, reencoded, payment, announcement, found, missing };
  }, { fixture, network, prefix: addressPrefix(network) });
  expect(result.encoded).toBe(fixture.privacy.metadata);
  expect(result.reencoded).toBe(fixture.privacy.metadata);
  expect(result.payment).toEqual(fixture.privacy.payment);
  expect(result.announcement).toBe(fixture.privacy.announcement);
  expect(result.found).toBe(fixture.privacy.scannerExpected);
  expect(result.missing).toBeNull();
}
