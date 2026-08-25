import { expect, test } from '@playwright/test';
import { boot, standardNetwork } from '../helpers.mjs';
import { startFaultServer, stopFaultServer } from '../resource/fault_server.mjs';

test('browser WebSocket transport fails closed and recovers after injected faults', async ({ page }) => {
  const server = await startFaultServer();
  try {
    await boot(page);
    const results = await page.evaluate(async ({ endpoint, networkName }) => {
      const sdk = globalThis.kaspaPortalSdk;
      async function invoke(mode) {
        const portal = new sdk.KaspaPortal(JSON.stringify({ network: networkName, endpoint, timeoutMs: '15000', maxRetries: 0 }));
        const network = portal.network();
        const client = network.client();
        try {
          const value = await client.call(131, Uint8Array.of(mode));
          return { ok: true, text: new TextDecoder().decode(value) };
        } catch (error) {
          return { ok: false, error: String(error) };
        } finally {
          if (typeof client.free === 'function') client.free();
          if (typeof network.free === 'function') network.free();
          if (typeof portal.free === 'function') portal.free();
        }
      }
      const first = [];
      for (let mode = 0; mode <= 8; mode += 1) first.push(await invoke(mode));
      const recovery = [];
      for (let index = 0; index < 16; index += 1) {
        recovery.push(await invoke(3 + (index % 5)));
        recovery.push(await invoke(0));
      }
      return { first, recovery };
    }, { endpoint: server.endpoint, networkName: standardNetwork() });

    for (const index of [0, 1, 2]) {
      expect(results.first[index].ok, `mode ${index}`).toBe(true);
      expect(results.first[index].text).toBe('fault-ok');
    }
    for (const index of [3, 4, 5, 6, 7, 8]) expect(results.first[index].ok, `mode ${index}`).toBe(false);
    expect(results.first[3].error).toContain('truncated RPC payload');
    expect(results.first[4].error).toContain('RPC response id mismatch');
    expect(results.first[5].error).toContain('RPC operation mismatch');
    expect(results.first[6].error).toContain('simulated remote error');
    expect(results.first[7].error).toContain('closed before RPC response');
    expect(results.first[8].error).toContain('non-binary frame');
    for (let index = 0; index < results.recovery.length; index += 2) {
      expect(results.recovery[index].ok).toBe(false);
      expect(results.recovery[index + 1]).toEqual({ ok: true, text: 'fault-ok' });
    }
  } finally {
    await stopFaultServer(server.child);
  }
});
