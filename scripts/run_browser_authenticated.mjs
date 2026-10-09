import puppeteer from '../frontend/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js';
import fs from 'fs';
const CHROME_PATH = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const LOCAL_BASE = process.env.LOCAL_BASE || 'http://localhost:3000';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';

async function runAuthenticatedE2E() {
  console.log('================================================================');
  console.log('THREATLENS AUTHENTICATED REAL BROWSER E2E TEST (CHROMIUM)');
  console.log('================================================================');

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu', '--window-size=1600,900']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1600, height: 900 });

  // 1. Visit root and inject JWT token into localStorage
  await page.goto(`${LOCAL_BASE}/`, { waitUntil: 'networkidle2' });
  await page.evaluate((tok) => {
    localStorage.setItem('threatlens_token', tok);
    localStorage.setItem('threatlens_role', 'Administrator');
  }, ADMIN_TOKEN);

  const authRoutes = [
    { path: '/dashboard/analyst', name: 'Analyst Triage & IOCs' },
    { path: '/dashboard/incidents', name: 'Incidents & Timelines' },
    { path: '/dashboard/cases', name: 'Case Management & Notes' },
    { path: '/dashboard/executive', name: 'Executive Posture & Reports' },
    { path: '/dashboard/builder', name: 'Dashboard Builder' },
    { path: '/dashboard/hunting', name: 'Hunting & Graph' },
    { path: '/dashboard/feeds', name: 'Feed Management & TAXII' },
  ];

  const results = [];

  for (const ar of authRoutes) {
    const consoleErrors = [];
    const http401s = [];
    const successfulApiRequests = [];

    const onConsole = msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    };
    const onResponse = resp => {
      const u = resp.url();
      if (u.includes('/api/v1/')) {
        if (resp.status() === 401) http401s.push(u);
        else if (resp.status() >= 200 && resp.status() < 400) successfulApiRequests.push(u);
      }
    };

    page.on('console', onConsole);
    page.on('response', onResponse);

    try {
      const resp = await page.goto(`${LOCAL_BASE}${ar.path}`, { waitUntil: 'networkidle2', timeout: 15000 });
      const status = resp?.status() || 200;
      const title = await page.title();

      const passed = http401s.length === 0;
      console.log(`[${passed ? 'PASS' : 'FAIL'}] ${ar.name.padEnd(30)} -> HTTP ${status} | Auth API Calls: ${successfulApiRequests.length} OK, ${http401s.length} 401s`);
      results.push({
        name: ar.name,
        path: ar.path,
        passed,
        successfulApiCalls: successfulApiRequests.length,
        http401Count: http401s.length,
        consoleErrorsCount: consoleErrors.length
      });
    } catch (err) {
      console.log(`[FAIL] ${ar.name} -> ${err.message}`);
      results.push({ name: ar.name, path: ar.path, passed: false, error: err.message });
    } finally {
      page.off('console', onConsole);
      page.off('response', onResponse);
    }
  }

  await browser.close();

  console.log('================================================================');
  console.log('AUTHENTICATED E2E SUMMARY:');
  const allPassed = results.every(r => r.passed);
  console.log(`ALL AUTHENTICATED ROUTES PASSED WITH ZERO 401s: ${allPassed}`);
  console.log('================================================================');
}

runAuthenticatedE2E().catch(console.error);
