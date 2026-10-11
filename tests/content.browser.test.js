// Run with: node --test "tests/*.test.js"
// The overlay is the only in-page UI: the legacy fixed "PhishGuard Risk Score" card
// (#phishguard-auto-score) must never appear, even when overlay.js or analysis.js is missing, and a
// card left behind by a stale copy of an older content script is removed. Loads the real content
// scripts into tests/browser/gmail-layout.html with a stubbed chrome API, in headless Chrome.
// Skipped if Chrome isn't found (set CHROME_PATH).
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { findChrome, launch, sleep } = require("./browser/cdp.js");

const chromePath = findChrome();
const FIXTURE = pathToFileURL(path.join(__dirname, "browser", "gmail-layout.html")).href;
const skip = chromePath ? false : "Chrome not found (set CHROME_PATH)";
const source = file => fs.readFileSync(path.join(__dirname, "..", file), "utf8");
const CHROME_STUB = `window.chrome = {
  runtime: { onMessage: { addListener() {} }, sendMessage() {}, getURL: () => "" },
  storage: { local: { get: async () => ({}) }, onChanged: { addListener() {} } }
};`;
const STALE_CARD = `{ const card = document.createElement("div"); card.id = "phishguard-auto-score";
  card.textContent = "PhishGuard Risk Score"; document.body.append(card); }`;
let page;

// Loads the given content scripts in manifest order. The fixture loads overlay.js itself, so it's
// removed first when a test leaves it out.
async function loadScripts(files, setup = "") {
  await page.viewport(1280, 800);
  await page.goto(FIXTURE);
  if (!files.includes("overlay.js")) await page.evaluate("delete window.PhishGuardOverlay");
  await page.evaluate(CHROME_STUB + setup);
  for (const file of files) if (file !== "overlay.js") await page.evaluate(source(file));
  await sleep(600); // the initial scan and the observer's 250 ms debounce
  await page.evaluate(`document.getElementById("msg").append(document.createElement("p"))`); // a Gmail-style DOM change
  await sleep(600);
  return page.evaluate(`({
    legacyCard: !!document.getElementById("phishguard-auto-score"),
    legacyText: document.body.innerText.includes("PhishGuard Risk Score"),
    badge: !!document.getElementById("phishguard-overlay-host")?.shadowRoot?.querySelector(".badge")
  })`);
}

before(async () => { if (chromePath) page = await launch(chromePath); });
after(async () => { if (page) await page.close(); });

test("with every script loaded, only the overlay badge is shown", { skip }, async () => {
  const ui = await loadScripts(["detector.js", "context.js", "analysis.js", "overlay.js", "content.js"]);
  assert.ok(ui.badge, "the overlay badge is missing");
  assert.ok(!ui.legacyCard && !ui.legacyText, "the legacy score card appeared");
});

test("if overlay.js or analysis.js didn't load, no legacy card is drawn instead", { skip }, async () => {
  for (const files of [["detector.js", "context.js", "analysis.js", "content.js"], ["detector.js", "context.js", "overlay.js", "content.js"]]) {
    const ui = await loadScripts(files);
    assert.ok(!ui.legacyCard && !ui.legacyText, `the legacy score card appeared with ${files.join(", ")}`);
  }
  assert.deepEqual(page.errors, []);
});

test("a legacy card left by a stale content script is removed", { skip }, async () => {
  const ui = await loadScripts(["detector.js", "context.js", "analysis.js", "overlay.js", "content.js"], STALE_CARD);
  assert.ok(!ui.legacyCard && !ui.legacyText, "the stale legacy card is still on the page");
  assert.ok(ui.badge);
});
