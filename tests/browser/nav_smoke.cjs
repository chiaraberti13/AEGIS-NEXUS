// Browser navigation smoke test (Node Playwright, CommonJS).
// Usage: node nav_smoke.cjs <baseURL>
// Loads the console and clicks through every nav view, asserting that each
// target section activates and that NO uncaught JS error fires along the way.
// This guards the app.js -> ES-module split (ADR 0003): a missing import or an
// undefined reference in any view surfaces as a pageerror and fails the test.
// console.error is intentionally ignored (safeGet logs it on legitimately
// failed fetches against an empty test DB).
const { chromium } = require("playwright");

const baseURL = process.argv[2];
const VIEWS = [
  "dashboard", "alerts", "iocs", "investigate",
  "cases", "relations", "audit", "health",
];

function fail(msg) {
  console.error("NAV SMOKE FAIL: " + msg);
  process.exit(1);
}

(async () => {
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage();
    const jsErrors = [];
    page.on("pageerror", (err) => jsErrors.push(String(err && err.message ? err.message : err)));

    await page.goto(baseURL, { waitUntil: "domcontentloaded" });
    // Wait for the app module to boot (the dashboard section starts active).
    await page.waitForSelector('section[data-view="dashboard"].active', { timeout: 20000 });

    for (const view of VIEWS) {
      await page.click(`button[data-view-target="${view}"]`);
      try {
        await page.waitForSelector(`section[data-view="${view}"].active`, { timeout: 10000 });
      } catch (e) {
        fail(`view "${view}" did not activate after nav click`);
      }
      // Give any async loader for the view a moment to run (and possibly throw).
      await page.waitForTimeout(400);
    }

    if (jsErrors.length) {
      fail("uncaught JS error(s) during navigation:\n  " + jsErrors.join("\n  "));
    }

    console.log("NAV SMOKE OK: all " + VIEWS.length + " views activated with no uncaught JS error");
    await browser.close();
    process.exit(0);
  } catch (err) {
    await browser.close();
    fail(String(err && err.message ? err.message : err));
  }
})();
