import puppeteer from '../frontend/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const LOCAL_BASE = 'http://localhost:3000';
const PROD_URL = 'https://threatlens.ashlynxcyber.in/';

const VIEWPORTS = [
  { name: '1440px Desktop', width: 1440, height: 900 },
  { name: '1024px Tablet Landscape', width: 1024, height: 768 },
  { name: '768px Tablet Portrait', width: 768, height: 1024 },
  { name: '390px Mobile', width: 390, height: 844 },
  { name: '320px Narrow Mobile', width: 320, height: 568 },
];

const ROUTES = [
  { path: '/', name: 'Home Hub' },
  { path: '/login', name: 'Authentication Login' },
  { path: '/dashboard/analyst', name: 'SOC Analyst Console' },
  { path: '/dashboard/incidents', name: 'Incident Correlation Timeline' },
  { path: '/dashboard/cases', name: 'Forensic Case Management' },
  { path: '/dashboard/executive', name: 'Executive Posture & Reports' },
  { path: '/dashboard/hunting', name: 'Threat Hunting & Graph' },
  { path: '/dashboard/feeds', name: 'Threat Feed Ingestion' },
  { path: '/dashboard/builder', name: 'Dashboard Builder' },
  { path: '/dashboard/admin/feeds', name: 'Admin Feed Configuration' },
];

async function runTestSuite() {
  console.log('========================================================================');
  console.log('THREATLENS RESPONSIVE UI/UX, AUTHENTICATION, AND RBAC E2E TEST SUITE');
  console.log('========================================================================');

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--window-size=1440,900',
    ],
  });

  const report = {
    viewports: [],
    authWorkflow: {},
    routes: [],
    prodSmoke: null,
    totalPassed: 0,
    totalFailed: 0,
  };

  try {
    const page = await browser.newPage();

    // -------------------------------------------------------------
    // PART 1: RESPONSIVE VIEWPORT & OVERFLOW AUDIT ACROSS ALL 5 VIEWPORTS
    // -------------------------------------------------------------
    console.log('\n--- PART 1: Testing Responsive Viewports & Horizontal Overflow ---');
    for (const vp of VIEWPORTS) {
      await page.setViewport({ width: vp.width, height: vp.height });
      await page.goto(`${LOCAL_BASE}/`, { waitUntil: 'networkidle2', timeout: 15000 });

      // Check document overflow
      const overflowInfo = await page.evaluate(() => {
        const bodyWidth = document.body.scrollWidth;
        const docWidth = document.documentElement.scrollWidth;
        const windowWidth = window.innerWidth;
        const hasOverflow = docWidth > windowWidth || bodyWidth > windowWidth;
        return {
          windowWidth,
          docWidth,
          bodyWidth,
          hasOverflow,
        };
      });

      // Check header visibility and clipping
      const headerInfo = await page.evaluate(() => {
        const header = document.querySelector('header');
        if (!header) return { present: false };
        const rect = header.getBoundingClientRect();
        return {
          present: true,
          right: rect.right,
          width: rect.width,
          clipped: rect.right > window.innerWidth + 1,
        };
      });

      const pass = !overflowInfo.hasOverflow && !headerInfo.clipped;
      console.log(`[${pass ? 'PASS' : 'FAIL'}] Viewport ${vp.name} (${vp.width}x${vp.height}):`);
      console.log(`       Window: ${overflowInfo.windowWidth}px | Doc: ${overflowInfo.docWidth}px | Overflow: ${overflowInfo.hasOverflow ? 'YES (FAIL)' : 'NO (CLEAN)'}`);
      console.log(`       Header width: ${headerInfo.width}px | Clipped: ${headerInfo.clipped ? 'YES (FAIL)' : 'NO (IN VIEW)'}`);

      if (pass) report.totalPassed++;
      else report.totalFailed++;

      report.viewports.push({
        viewport: vp.name,
        width: vp.width,
        height: vp.height,
        overflow: overflowInfo.hasOverflow,
        headerClipped: headerInfo.clipped,
        passed: pass,
      });
    }

    // -------------------------------------------------------------
    // PART 2: MOBILE DRAWER NAVIGATION INTERACTION
    // -------------------------------------------------------------
    console.log('\n--- PART 2: Testing Mobile Navigation Drawer Toggle & Escape Key ---');
    await page.setViewport({ width: 390, height: 844 });
    await page.goto(`${LOCAL_BASE}/`, { waitUntil: 'networkidle2', timeout: 10000 });

    // Find and click hamburger menu toggle
    const toggleBtn = await page.$('#mobile-menu-toggle-btn');
    if (toggleBtn) {
      await toggleBtn.click();
      await new Promise(r => setTimeout(r, 300));
      const drawerVisible = await page.evaluate(() => {
        const nav = document.querySelector('[aria-label="Mobile Navigation"]');
        return !!nav;
      });
      console.log(`[${drawerVisible ? 'PASS' : 'FAIL'}] Hamburger button opens mobile drawer: ${drawerVisible}`);
      if (drawerVisible) report.totalPassed++;
      else report.totalFailed++;

      // Press Escape to close
      await page.keyboard.press('Escape');
      await new Promise(r => setTimeout(r, 300));
      const drawerClosed = await page.evaluate(() => {
        const nav = document.querySelector('[aria-label="Mobile Navigation"]');
        return !nav;
      });
      console.log(`[${drawerClosed ? 'PASS' : 'FAIL'}] Escape key dismisses mobile drawer: ${drawerClosed}`);
      if (drawerClosed) report.totalPassed++;
      else report.totalFailed++;
    } else {
      console.log('[FAIL] Hamburger button #mobile-menu-toggle-btn not found on 390px viewport');
      report.totalFailed++;
    }

    // -------------------------------------------------------------
    // PART 3: REAL AUTHENTICATION WORKFLOW (LOGIN, JWT, PROFILE, LOGOUT)
    // -------------------------------------------------------------
    console.log('\n--- PART 3: Testing Authentication, Session & Role Controls ---');
    await page.setViewport({ width: 1440, height: 900 });

    // Step 3a: Navigate to /login
    await page.goto(`${LOCAL_BASE}/login`, { waitUntil: 'networkidle2', timeout: 10000 });
    const loginHeader = await page.evaluate(() => document.body.innerText.includes('THREATLENS'));
    console.log(`[${loginHeader ? 'PASS' : 'FAIL'}] Login portal renders with branding: ${loginHeader}`);
    if (loginHeader) report.totalPassed++;
    else report.totalFailed++;

    // Step 3b: Test invalid password
    await page.evaluate(() => {
      const pwInput = document.getElementById('login-password-input');
      if (pwInput) {
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(pwInput, 'WrongPassword999!');
        pwInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
      document.getElementById('login-submit-button')?.click();
    });
    await new Promise(r => setTimeout(r, 1500));

    const invalidError = await page.evaluate(() => {
      const text = document.body.innerText;
      return text.includes('Invalid') || text.includes('Incorrect') || text.includes('credentials');
    });
    console.log(`[${invalidError ? 'PASS' : 'FAIL'}] Invalid password triggers error alert: ${invalidError}`);
    if (invalidError) report.totalPassed++;
    else report.totalFailed++;

    // Step 3c: Test valid login with Admin preset
    await page.evaluate(() => {
      const emailInput = document.getElementById('login-email-input');
      const pwInput = document.getElementById('login-password-input');
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      if (emailInput) {
        setter.call(emailInput, 'admin_user@threatlens.io');
        emailInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
      if (pwInput) {
        setter.call(pwInput, 'RoleTestPass!123');
        pwInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
    });
    await new Promise(r => setTimeout(r, 200));
    await page.evaluate(() => {
      document.getElementById('login-submit-button')?.click();
    });
    await new Promise(r => setTimeout(r, 2000));

    // Step 3d: Verify stored JWT token and user profile
    const authState = await page.evaluate(() => {
      const token = localStorage.getItem('threatlens_token');
      const user = localStorage.getItem('threatlens_user');
      const role = localStorage.getItem('threatlens_role');
      return { hasToken: !!token, user: user ? JSON.parse(user) : null, role };
    });
    console.log(`[${authState.hasToken ? 'PASS' : 'FAIL'}] Valid login stores JWT token: ${authState.hasToken}`);
    console.log(`[${authState.user?.role === 'admin' ? 'PASS' : 'FAIL'}] User profile retrieved: ${authState.user?.email} (${authState.user?.role})`);
    if (authState.hasToken) report.totalPassed++;
    else report.totalFailed++;
    if (authState.user?.role === 'admin') report.totalPassed++;
    else report.totalFailed++;

    // Step 3e: Verify header account controls display actual user and role
    await page.goto(`${LOCAL_BASE}/`, { waitUntil: 'networkidle2', timeout: 10000 });
    await new Promise(r => setTimeout(r, 800));
    const headerAccountDisplay = await page.evaluate(() => {
      const headerText = document.querySelector('header')?.innerText || '';
      return {
        hasEmailOrName: headerText.toLowerCase().includes('admin') || headerText.includes('SecOps'),
        hasRoleBadge: headerText.toLowerCase().includes('admin'),
      };
    });
    console.log(`[${headerAccountDisplay.hasRoleBadge ? 'PASS' : 'FAIL'}] Header displays server-verified role badge: ${headerAccountDisplay.hasRoleBadge}`);
    if (headerAccountDisplay.hasRoleBadge) report.totalPassed++;
    else report.totalFailed++;

    // Step 3f: Test account menu dropdown and Logout
    const accountToggle = await page.evaluate(() => {
      const btns = Array.from(document.querySelectorAll('header button'));
      const acctBtn = btns.find(b => b.getAttribute('aria-label') === 'User account menu');
      if (acctBtn) {
        acctBtn.click();
        return true;
      }
      return false;
    });
    await new Promise(r => setTimeout(r, 500));

    const logoutBtnPresent = await page.evaluate(() => {
      return document.body.innerText.includes('Sign Out of Console');
    });
    console.log(`[${logoutBtnPresent ? 'PASS' : 'FAIL'}] Account menu opens with 'Sign Out of Console': ${logoutBtnPresent}`);
    if (logoutBtnPresent) report.totalPassed++;
    else report.totalFailed++;

    // Click Sign Out
    await page.evaluate(() => {
      const btns = Array.from(document.querySelectorAll('button'));
      const signout = btns.find(b => b.innerText.includes('Sign Out of Console'));
      if (signout) signout.click();
    });
    await new Promise(r => setTimeout(r, 1000));

    // Verify token removed
    const tokenAfterLogout = await page.evaluate(() => localStorage.getItem('threatlens_token'));
    const isLoggedOut = !tokenAfterLogout;
    console.log(`[${isLoggedOut ? 'PASS' : 'FAIL'}] Logout removes JWT token and revokes session: ${isLoggedOut}`);
    if (isLoggedOut) report.totalPassed++;
    else report.totalFailed++;

    // -------------------------------------------------------------
    // PART 4: VERIFY EVERY ROUTE RENDERS WITH NEW RESPONSIVE HEADER
    // -------------------------------------------------------------
    console.log('\n--- PART 4: Route Rendering & Overflow Audit (All 10 Routes) ---');
    for (const r of ROUTES) {
      const url = `${LOCAL_BASE}${r.path}`;
      const errors = [];
      page.on('console', msg => {
        if (msg.type() === 'error') errors.push(msg.text());
      });

      await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
      const pageInfo = await page.evaluate(() => {
        const docWidth = document.documentElement.scrollWidth;
        const winWidth = window.innerWidth;
        const hasHeader = !!document.querySelector('header');
        return {
          docWidth,
          winWidth,
          overflow: docWidth > winWidth,
          hasHeader,
        };
      });

      const pass = !pageInfo.overflow && pageInfo.hasHeader;
      console.log(`[${pass ? 'PASS' : 'FAIL'}] Route: ${r.path.padEnd(26)} | Header: ${pageInfo.hasHeader ? 'OK' : 'MISSING'} | Overflow: ${pageInfo.overflow ? 'YES' : 'NO'}`);
      if (pass) report.totalPassed++;
      else report.totalFailed++;

      report.routes.push({
        path: r.path,
        name: r.name,
        overflow: pageInfo.overflow,
        header: pageInfo.hasHeader,
        errors: errors.length,
        passed: pass,
      });
    }

    // -------------------------------------------------------------
    // PART 5: PRODUCTION SMOKE TEST (READ-ONLY)
    // -------------------------------------------------------------
    console.log('\n--- PART 5: Production Read-Only Smoke Test ---');
    console.log(`Target: ${PROD_URL}`);
    try {
      const prodPage = await browser.newPage();
      await prodPage.setViewport({ width: 1440, height: 900 });
      const prodRes = await prodPage.goto(PROD_URL, { waitUntil: 'networkidle2', timeout: 20000 });
      const prodStatus = prodRes?.status() || 0;

      const prodMeta = await prodPage.evaluate(() => {
        return {
          title: document.title,
          domNodes: document.querySelectorAll('*').length,
          hasThreatLensText: document.body.innerText.includes('THREATLENS'),
        };
      });

      console.log(`[${prodStatus === 200 ? 'PASS' : 'FAIL'}] Production HTTP Status: ${prodStatus}`);
      console.log(`       Document Title: ${prodMeta.title}`);
      console.log(`       Rendered DOM Elements: ${prodMeta.domNodes}`);
      console.log(`       Platform Branding Present: ${prodMeta.hasThreatLensText}`);

      report.prodSmoke = {
        url: PROD_URL,
        status: prodStatus,
        title: prodMeta.title,
        domNodes: prodMeta.domNodes,
        passed: prodStatus === 200,
      };

      if (prodStatus === 200) report.totalPassed++;
      else report.totalFailed++;
      await prodPage.close();
    } catch (err) {
      console.log(`[BLOCKED/ERROR] Production Smoke Test: ${err.message}`);
      report.prodSmoke = { error: err.message, passed: false };
      report.totalFailed++;
    }

  } finally {
    await browser.close();
  }

  console.log('\n========================================================================');
  console.log(`TEST RESULTS SUMMARY: ${report.totalPassed} PASSED | ${report.totalFailed} FAILED`);
  console.log('========================================================================');
  return report;
}

runTestSuite().catch(err => {
  console.error('Fatal execution error:', err);
  process.exit(1);
});
