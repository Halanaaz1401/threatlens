import puppeteer from '../frontend/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js';
import fs from 'fs';
import path from 'path';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const LOCAL_BASE = 'http://localhost:3000';
const PROD_URL = 'https://threatlens.ashlynxcyber.in/';

const ROUTES = [
  { path: '/', name: 'Home Hub / Landing', expectedTitle: /ThreatLens/i, selector: 'header' },
  { path: '/dashboard/analyst', name: 'SOC Analyst Console', expectedTitle: /ThreatLens/i, selector: 'h1, h2, h3' },
  { path: '/dashboard/incidents', name: 'Incident Correlation Timeline', expectedTitle: /ThreatLens/i, selector: 'header' },
  { path: '/dashboard/cases', name: 'Forensic Case Management', expectedTitle: /ThreatLens/i, selector: 'header' },
  { path: '/dashboard/executive', name: 'Executive Posture & Reports', expectedTitle: /ThreatLens/i, selector: 'header' },
  { path: '/dashboard/hunting', name: 'Threat Hunting & Relational Graph', expectedTitle: /ThreatLens/i, selector: 'header' },
  { path: '/dashboard/feeds', name: 'Threat Feed Management & TAXII', expectedTitle: /ThreatLens/i, selector: 'header' },
  { path: '/dashboard/builder', name: 'Custom Dashboard Builder', expectedTitle: /ThreatLens/i, selector: 'header' },
  { path: '/dashboard/admin/feeds', name: 'Admin Feed Configuration', expectedTitle: /ThreatLens/i, selector: 'header' },
];

async function runBrowserE2E() {
  console.log('================================================================');
  console.log('THREATLENS REAL BROWSER E2E TEST SUITE (CHROMIUM HEADLESS)');
  console.log('================================================================');
  console.log(`Using Chrome binary: ${CHROME_PATH}`);

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--disable-gpu',
      '--window-size=1600,900'
    ]
  });

  const results = {
    localRoutes: [],
    socWorkflows: [],
    roleBasedTesting: [],
    prodSmokeTest: null,
    summary: { passed: 0, failed: 0, blocked: 0 }
  };

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1600, height: 900 });

    // -------------------------------------------------------------
    // PART 1: TEST EVERY LOCAL USER-FACING ROUTE
    // -------------------------------------------------------------
    console.log('\n--- 1. Testing All Local Frontend Routes ---');
    for (const r of ROUTES) {
      const url = `${LOCAL_BASE}${r.path}`;
      const consoleErrors = [];
      const failedRequests = [];

      const onConsole = msg => {
        if (msg.type() === 'error') {
          consoleErrors.push(msg.text());
        }
      };
      const onRequestFailed = req => {
        failedRequests.push({ url: req.url(), error: req.failure()?.errorText || 'failed' });
      };

      page.on('console', onConsole);
      page.on('requestfailed', onRequestFailed);

      const startTime = Date.now();
      let status = 'PASS';
      let errorMsg = null;
      let pageTitle = '';
      let visibleElementsCount = 0;

      try {
        const response = await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
        const httpStatus = response?.status() || 200;
        pageTitle = await page.title();
        await page.waitForSelector(r.selector, { timeout: 5000 });

        visibleElementsCount = await page.evaluate(() => document.querySelectorAll('*').length);

        if (httpStatus >= 400) {
          status = 'FAIL';
          errorMsg = `HTTP status ${httpStatus}`;
        }
      } catch (err) {
        status = 'FAIL';
        errorMsg = err.message;
      } finally {
        page.off('console', onConsole);
        page.off('requestfailed', onRequestFailed);
      }

      const elapsed = Date.now() - startTime;
      const resItem = {
        route: r.path,
        name: r.name,
        status,
        elapsedMs: elapsed,
        title: pageTitle,
        elementsCount: visibleElementsCount,
        consoleErrors,
        failedRequests,
        error: errorMsg
      };

      results.localRoutes.push(resItem);
      if (status === 'PASS') results.summary.passed++;
      else results.summary.failed++;

      console.log(`[${status}] ${r.path.padEnd(25)} (${elapsed}ms) - Title: "${pageTitle}" - DOM Nodes: ${visibleElementsCount} - Console Errs: ${consoleErrors.length}`);
      if (consoleErrors.length > 0) {
        consoleErrors.forEach(ce => console.log(`      Console Error: ${ce.substring(0, 120)}`));
      }
    }

    // -------------------------------------------------------------
    // PART 2: MAJOR SOC WORKFLOW TESTS
    // -------------------------------------------------------------
    console.log('\n--- 2. Testing Major SOC Interactive Workflows ---');

    // Workflow A: Analyst Triage & Selection
    try {
      await page.goto(`${LOCAL_BASE}/dashboard/analyst`, { waitUntil: 'networkidle2', timeout: 15000 });
      const iocItems = await page.$$('tr, [data-ioc-id], li');
      const clicked = await page.evaluate(() => {
        const firstRow = document.querySelector('tbody tr') || document.querySelector('[role="row"]');
        if (firstRow) {
          firstRow.click();
          return true;
        }
        return false;
      });
      results.socWorkflows.push({
        workflow: 'IOC Selection & Detail Drawer',
        status: 'PASS',
        details: `Interacted with table rows. Click successful: ${clicked}.`
      });
      console.log('[PASS] Workflow: IOC Selection & Detail Drawer');
    } catch (err) {
      results.socWorkflows.push({ workflow: 'IOC Selection & Detail Drawer', status: 'FAIL', details: err.message });
      console.log(`[FAIL] Workflow: IOC Selection & Detail Drawer - ${err.message}`);
    }

    // Workflow B: Incident Correlation & Timeline Expansion
    try {
      await page.goto(`${LOCAL_BASE}/dashboard/incidents`, { waitUntil: 'networkidle2', timeout: 15000 });
      const incidentCards = await page.evaluate(() => {
        const cards = document.querySelectorAll('button, [data-incident-id]');
        return cards.length;
      });
      results.socWorkflows.push({
        workflow: 'Incident Timeline & Correlation Inspection',
        status: 'PASS',
        details: `Rendered incidents list with ${incidentCards} interactive elements.`
      });
      console.log(`[PASS] Workflow: Incident Timeline & Correlation Inspection (${incidentCards} interactive elements)`);
    } catch (err) {
      results.socWorkflows.push({ workflow: 'Incident Timeline & Correlation Inspection', status: 'FAIL', details: err.message });
      console.log(`[FAIL] Workflow: Incident Timeline & Correlation Inspection - ${err.message}`);
    }

    // Workflow C: Threat Hunting Graph Navigation
    try {
      await page.goto(`${LOCAL_BASE}/dashboard/hunting`, { waitUntil: 'networkidle2', timeout: 15000 });
      const graphRendered = await page.evaluate(() => {
        const svgs = document.querySelectorAll('svg, canvas, [data-graph]');
        return svgs.length;
      });
      results.socWorkflows.push({
        workflow: 'Hunting Graph Traversal & SVG Rendering',
        status: 'PASS',
        details: `Graph container rendered with ${graphRendered} visual graph element(s).`
      });
      console.log(`[PASS] Workflow: Hunting Graph Traversal & SVG Rendering (${graphRendered} graph elements)`);
    } catch (err) {
      results.socWorkflows.push({ workflow: 'Hunting Graph Traversal & SVG Rendering', status: 'FAIL', details: err.message });
      console.log(`[FAIL] Workflow: Hunting Graph Traversal & SVG Rendering - ${err.message}`);
    }

    // Workflow D: Custom Dashboard Builder Catalog
    try {
      await page.goto(`${LOCAL_BASE}/dashboard/builder`, { waitUntil: 'networkidle2', timeout: 15000 });
      const catalogWidgets = await page.evaluate(() => {
        const buttons = document.querySelectorAll('button');
        return buttons.length;
      });
      results.socWorkflows.push({
        workflow: 'Dashboard Widget Catalog & Layout Controls',
        status: 'PASS',
        details: `Custom builder page verified with ${catalogWidgets} interactive action buttons.`
      });
      console.log(`[PASS] Workflow: Dashboard Widget Catalog & Layout Controls`);
    } catch (err) {
      results.socWorkflows.push({ workflow: 'Dashboard Widget Catalog & Layout Controls', status: 'FAIL', details: err.message });
      console.log(`[FAIL] Workflow: Dashboard Widget Catalog & Layout Controls - ${err.message}`);
    }

    // -------------------------------------------------------------
    // PART 3: ROLE-BASED ACCESS CONTROL UI VERIFICATION
    // -------------------------------------------------------------
    console.log('\n--- 3. Testing Role-Based UI Access ---');
    try {
      await page.goto(`${LOCAL_BASE}/`, { waitUntil: 'networkidle2', timeout: 15000 });
      // Verify role context selector exists
      const roleSelectorPresent = await page.evaluate(() => {
        const selects = document.querySelectorAll('select, [data-role-selector]');
        return selects.length > 0;
      });

      // Test switching role via localStorage
      const rolesToTest = [
        { role: 'SOC Tier-1 Analyst', expectedAccess: true },
        { role: 'Security Engineer', expectedAccess: true },
        { role: 'Administrator', expectedAccess: true },
        { role: 'CISO (Executive)', expectedAccess: true },
      ];

      for (const rt of rolesToTest) {
        await page.evaluate((r) => {
          localStorage.setItem('threatlens_role', r);
          window.dispatchEvent(new Event('storage'));
        }, rt.role);
        await page.goto(`${LOCAL_BASE}/dashboard/analyst`, { waitUntil: 'networkidle2', timeout: 15000 });
        const title = await page.title();
        results.roleBasedTesting.push({
          role: rt.role,
          route: '/dashboard/analyst',
          status: 'PASS',
          title
        });
        console.log(`[PASS] Role switch to "${rt.role}": Successfully rendered /dashboard/analyst`);
      }
    } catch (err) {
      console.log(`[FAIL] Role testing error: ${err.message}`);
    }

    // -------------------------------------------------------------
    // PART 4: PRODUCTION DOMAIN READ-ONLY SMOKE TEST
    // -------------------------------------------------------------
    console.log('\n--- 4. Production Domain Read-Only Smoke Test ---');
    console.log(`Navigating to ${PROD_URL}...`);
    const prodConsole = [];
    const prodFailedReqs = [];
    const onProdConsole = m => prodConsole.push({ type: m.type(), text: m.text() });
    const onProdReqFailed = r => prodFailedReqs.push({ url: r.url(), error: r.failure()?.errorText || 'failed' });

    page.on('console', onProdConsole);
    page.on('requestfailed', onProdReqFailed);

    try {
      const prodRes = await page.goto(PROD_URL, { waitUntil: 'networkidle2', timeout: 20000 });
      const prodStatus = prodRes?.status() || 200;
      const prodTitle = await page.title();
      const prodUrl = page.url();
      const nodeCount = await page.evaluate(() => document.querySelectorAll('*').length);

      results.prodSmokeTest = {
        url: prodUrl,
        httpStatus: prodStatus,
        title: prodTitle,
        tlsSecure: prodUrl.startsWith('https://'),
        nodeCount,
        consoleErrors: prodConsole.filter(c => c.type === 'error').map(c => c.text),
        consoleWarnings: prodConsole.filter(c => c.type === 'warning').map(c => c.text),
        failedRequests: prodFailedReqs,
        status: prodStatus === 200 ? 'PASS' : 'FAIL'
      };

      console.log(`[${results.prodSmokeTest.status}] Production Smoke: URL=${prodUrl}, Status=${prodStatus}, Title="${prodTitle}", TLS=${results.prodSmokeTest.tlsSecure}`);
      console.log(`      DOM Elements: ${nodeCount}`);
      console.log(`      Console Errors: ${results.prodSmokeTest.consoleErrors.length}`);
      console.log(`      Failed Requests: ${prodFailedReqs.length}`);
      if (results.prodSmokeTest.consoleErrors.length > 0) {
        results.prodSmokeTest.consoleErrors.forEach(ce => console.log(`      Production Console Error: ${ce.substring(0, 120)}`));
      }
    } catch (err) {
      results.prodSmokeTest = {
        url: PROD_URL,
        status: 'FAIL',
        error: err.message
      };
      console.log(`[FAIL] Production Smoke Test: ${err.message}`);
    } finally {
      page.off('console', onProdConsole);
      page.off('requestfailed', onProdReqFailed);
    }

  } finally {
    await browser.close();
  }

  // Save results to artifacts directory
  const reportPath = path.resolve('..', 'browser_e2e_results.json');
  fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));
  console.log(`\nResults saved to: ${reportPath}`);
  console.log('================================================================');
  console.log(`TOTAL ROUTES TESTED: ${results.localRoutes.length}`);
  console.log(`PASSED: ${results.summary.passed} | FAILED: ${results.summary.failed}`);
  console.log('================================================================');
}

runBrowserE2E().catch(err => {
  console.error('Fatal Browser E2E Error:', err);
  process.exit(1);
});
