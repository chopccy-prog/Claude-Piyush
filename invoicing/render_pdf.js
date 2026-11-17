// Fallback HTML -> PDF renderer used by make_invoice.py when the Python
// Playwright package is not installed.  Usage: node render_pdf.js in.html out.pdf
const { chromium } = require('playwright');
const { pathToFileURL } = require('url');

(async () => {
  const [, , input, output] = process.argv;
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto(pathToFileURL(require('path').resolve(input)).href, { waitUntil: 'networkidle' });
  await page.pdf({ path: output, format: 'A4', printBackground: true,
                   margin: { top: '0', right: '0', bottom: '0', left: '0' } });
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
