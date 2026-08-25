import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.KASPA_PORTAL_E2E_BROWSER_PORT || '4173');
const baseURL = `http://127.0.0.1:${port}`;
const site = process.env.KASPA_PORTAL_E2E_SITE;
if (!site) throw new Error('KASPA_PORTAL_E2E_SITE is required');

export default defineConfig({
  testDir: './tests',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['line']],
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node ./serve.mjs',
    url: baseURL,
    reuseExistingServer: false,
    timeout: 30_000,
    env: {
      ...process.env,
      KASPA_PORTAL_E2E_BROWSER_PORT: String(port),
      KASPA_PORTAL_E2E_SITE: site,
    },
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testMatch: /cross-browser\.spec\.mjs|storage\.spec\.mjs/ },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, testMatch: /cross-browser\.spec\.mjs|storage\.spec\.mjs/ },
  ],
});
