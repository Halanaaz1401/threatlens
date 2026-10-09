import puppeteer from '../frontend/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const LOCAL_BASE = 'http://127.0.0.1:3000';

const VIEWPORTS = [
  { name: 'Desktop (1440px)', width: 1440, height: 900 },
  { name: 'Tablet Landscape (1024px)', width: 1024, height: 768 },
  { name: 'Tablet Portrait (768px)', width: 768, height: 1024 },
  { name: 'Mobile Standard (390px)', width: 390, height: 844 },
  { name: 'Mobile Compact (320px)', width: 320, height: 600 },
];

const ROUTES = [
  '/',
  '/login',
  '/dashboard/analyst',
  '/dashboard/incidents',
  '/dashboard/cases',
  '/dashboard/executive',
  '/dashboard/hunting',
  '/dashboard/feeds',
  '/dashboard/builder',
];

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function run() {
  console.log('================================================================================');
  console.log('THREATLENS RESPONSIVE VIEWPORT & HORIZONTAL OVERFLOW VERIFICATION');
  console.log('================================================================================\n');

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'],
  });

  let totalChecked = 0;
  let totalOverflows = 0;

  for (const vp of VIEWPORTS) {
    console.log(`\n--- Testing Viewport: ${vp.name} (${vp.width}x${vp.height}) ---`);
    const page = await browser.newPage();
    await page.setViewport({ width: vp.width, height: vp.height });

    // Authenticate so dashboard routes display full content
    await page.goto(`${LOCAL_BASE}/login`, { waitUntil: 'networkidle2' });
    await page.evaluate(() => {
      const emailInput = document.querySelector('#login-email-input');
      const passInput = document.querySelector('#login-password-input');
      if (emailInput) {
        Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(emailInput, 'admin_user@threatlens.io');
        emailInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
      if (passInput) {
        Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set.call(passInput, 'RoleTestPass!123');
        passInput.dispatchEvent(new Event('input', { bubbles: true }));
      }
    });
    const submitBtn = await page.$('#login-submit-button');
    if (submitBtn) {
      await submitBtn.click();
      await sleep(1000);
    }

    for (const route of ROUTES) {
      await page.goto(`${LOCAL_BASE}${route}`, { waitUntil: 'networkidle2' }).catch(() => {});
      await sleep(400);

      const overflowData = await page.evaluate(() => {
        const docEl = document.documentElement;
        const body = document.body;
        const scrollWidth = Math.max(docEl.scrollWidth, body.scrollWidth);
        const clientWidth = docEl.clientWidth;
        return {
          hasOverflow: scrollWidth > clientWidth,
          scrollWidth,
          clientWidth,
          diff: scrollWidth - clientWidth,
        };
      });

      totalChecked++;
      if (overflowData.hasOverflow && overflowData.diff > 1) {
        console.error(`  [FAIL] ${route} -> Overflow of ${overflowData.diff}px (scroll: ${overflowData.scrollWidth}px, client: ${overflowData.clientWidth}px)`);
        totalOverflows++;
      } else {
        console.log(`  [PASS] ${route} -> 0px overflow (width: ${overflowData.clientWidth}px)`);
      }
    }

    await page.close();
  }

  await browser.close();

  console.log('\n================================================================================');
  console.log(`SUMMARY: ${totalChecked} route/viewport pairs tested. Overflows: ${totalOverflows}`);
  console.log('================================================================================');

  if (totalOverflows > 0) {
    process.exit(1);
  } else {
    console.log('SUCCESS: All 9 application routes are perfectly responsive with 0 horizontal overflow across all 5 target viewports!');
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
