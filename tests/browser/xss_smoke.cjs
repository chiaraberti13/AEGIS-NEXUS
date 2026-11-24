// Browser XSS smoke test (Node Playwright, CommonJS).
// Usage: node xss_smoke.cjs <baseURL>
// Loads the console, opens an event whose captured command contains hostile
// markup, and asserts the attacker payload is rendered as inert text — no
// dialog fires and no script executes (window.__xss__ stays undefined).
const { chromium } = require("playwright");

const baseURL = process.argv[2];
const MARKER = "window.__xss__"; // substring of the injected payload

function fail(msg) {
  console.error("XSS SMOKE FAIL: " + msg);
  process.exit(1);
}

(async () => {
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage();
    let dialogFired = false;
    page.on("dialog", async (d) => { dialogFired = true; await d.dismiss(); });

    await page.goto(baseURL, { waitUntil: "domcontentloaded" });
    // Wait for a real feed row (the source-IP cell exists only on data rows).
    await page.waitForSelector("#dashboard-feed tr td:nth-child(2)", { timeout: 20000 });
    await page.click("#dashboard-feed tr");

    // Poll for the payload text to appear as inert DOM text in the detail view.
    let rendered = false;
    for (let i = 0; i < 20; i++) {
      const text = await page.evaluate(() => document.body.innerText || "");
      if (text.includes(MARKER)) { rendered = true; break; }
      await page.waitForTimeout(500);
    }

    const executed = await page.evaluate(() => window.__xss__);
    if (dialogFired) fail("a dialog (alert) fired — script executed");
    if (executed) fail("window.__xss__ was set — script executed");
    if (!rendered) fail("hostile payload text was not rendered (cannot confirm escaping path)");

    console.log("XSS SMOKE OK: payload rendered as text, no execution");
    await browser.close();
    process.exit(0);
  } catch (err) {
    await browser.close();
    fail(String(err && err.message ? err.message : err));
  }
})();
