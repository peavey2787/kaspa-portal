import { readFile } from 'node:fs/promises';
import { expect } from '@playwright/test';

export const DEFAULT_STANDARD_NETWORK = 'testnet-10';
export const DEFAULT_STANDARD_GENESIS_HASH = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370';
export const DEFAULT_STANDARD_ENDPOINT = 'wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh';
export const DEFAULT_COVENANT_NETWORK = 'testnet-12';
export const INDEXED_FIXTURE_TXID = '5201b38ed218ca4cf392a71ce446d75fd667b954e2efdebec1acf83e48892e2a';

export async function readJsonEnv(name, required = true) {
  const path = process.env[name];
  if (!path) {
    if (required) throw new Error(`${name} is required`);
    return null;
  }
  return JSON.parse(await readFile(path, 'utf8'));
}

export async function boot(page) {
  await page.goto('/');
  await page.evaluate(async () => {
    const sdk = await import('/pkg/kaspa_portal.js');
    await sdk.default();
    globalThis.kaspaPortalSdk = sdk;
  });
  const exports = await page.evaluate(() => Object.keys(globalThis.kaspaPortalSdk).sort());
  expect(exports).toContain('KaspaPortal');
  expect(exports).toContain('KaspaIndexer');
  return exports;
}

export function standardNetwork() {
  return process.env.KASPA_PORTAL_E2E_STANDARD_NETWORK || DEFAULT_STANDARD_NETWORK;
}

export function standardEndpoint() {
  return process.env.KASPA_PORTAL_E2E_STANDARD_ENDPOINT
    || process.env.KASPA_PORTAL_E2E_ENDPOINT
    || DEFAULT_STANDARD_ENDPOINT;
}

export function standardGenesisHash() {
  return process.env.KASPA_PORTAL_E2E_STANDARD_GENESIS_HASH || DEFAULT_STANDARD_GENESIS_HASH;
}

export function covenantNetwork() {
  return process.env.KASPA_PORTAL_E2E_COVENANT_NETWORK || DEFAULT_COVENANT_NETWORK;
}

export function addressPrefix(network) {
  if (network === 'mainnet') return 'kaspa';
  if (network === 'simnet') return 'kaspasim';
  if (network === 'devnet') return 'kaspadev';
  return 'kaspatest';
}


export function standardNetworkConfig() {
  const network = standardNetwork();
  return {
    network,
    endpoint: standardEndpoint(),
    genesisHash: standardGenesisHash(),
    addressPrefix: addressPrefix(network),
  };
}

export function bytes(hex) {
  if (hex.length % 2) throw new Error('hex length must be even');
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}
