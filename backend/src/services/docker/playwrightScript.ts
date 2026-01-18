import { PLAYWRIGHT_VERSION } from './constants';

/**
 * Generates the Playwright script that runs inside the Docker container
 * to visit a URL and capture all network requests.
 */
export function generatePlaywrightScript(url: string): string {
  const escapedUrl = url.replace(/'/g, "\\'");

  return `
const { chromium } = require('playwright-core');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  
  const networkRequests = [];
  
  page.on('request', (request) => {
    try {
      const reqUrl = request.url();
      const urlObj = new URL(reqUrl);
      networkRequests.push({
        url: reqUrl,
        domain: urlObj.hostname,
        resourceType: request.resourceType()
      });
    } catch {}
  });
  
  page.on('response', (response) => {
    try {
      const reqUrl = response.url();
      const existing = networkRequests.find(r => r.url === reqUrl);
      if (existing) {
        existing.status = response.status();
      }
    } catch {}
  });
  
  try {
    await page.goto('${escapedUrl}', { 
      waitUntil: 'networkidle', 
      timeout: 30000 
    });
    
    const title = await page.title();
    const finalUrl = page.url();
    
    console.log(JSON.stringify({
      success: true,
      pageTitle: title,
      finalUrl: finalUrl,
      networkRequests: networkRequests
    }));
  } catch (err) {
    console.log(JSON.stringify({
      success: false,
      error: err.message,
      networkRequests: networkRequests
    }));
  } finally {
    await browser.close();
  }
})();
`;
}

/**
 * Wraps the Playwright script in a shell command that installs
 * playwright-core and runs the script inside the container.
 */
export function wrapScriptForContainer(script: string): string {
  return `
cd /tmp && 
npm init -y --silent 2>/dev/null &&
npm install --silent playwright-core@${PLAYWRIGHT_VERSION} 2>/dev/null &&
node << 'SCRIPT_EOF'
${script}
SCRIPT_EOF
`;
}
