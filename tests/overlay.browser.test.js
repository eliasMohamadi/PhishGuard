// Run with: node --test "tests/*.test.js"
// Runs tests/browser/overlay-test.html in headless Chrome (virtual time, so the 12 s guard is
// instant) and reads the results it writes to <body data-results>. Skipped if Chrome isn't found;
// set CHROME_PATH to point at a Chrome or Chromium binary.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { pathToFileURL } = require("node:url");

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser"
].filter(Boolean);
const chrome = CANDIDATES.find(p => fs.existsSync(p));

test("overlay behaviour in a real DOM", { skip: chrome ? false : "Chrome not found (set CHROME_PATH)" }, () => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "phishguard-overlay-"));
  try {
    const page = pathToFileURL(path.join(__dirname, "browser", "overlay-test.html")).href;
    const html = execFileSync(chrome, [
      "--headless=new", "--disable-gpu", "--no-first-run", `--user-data-dir=${profile}`,
      "--virtual-time-budget=30000", "--dump-dom", page
    ], { encoding: "utf8", timeout: 60000 });
    const match = html.match(/data-results="([^"]*)"/);
    assert.ok(match, "the test page did not finish");
    const results = JSON.parse(match[1].replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
    assert.ok(results.length >= 10, `only ${results.length} checks ran`);
    const failed = results.filter(r => !r.ok);
    assert.deepEqual(failed, [], failed.map(f => `${f.name}: ${f.error}`).join("\n"));
  } finally {
    fs.rmSync(profile, { recursive: true, force: true });
  }
});
