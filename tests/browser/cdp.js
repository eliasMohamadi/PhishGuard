// Minimal Chrome DevTools Protocol driver for browser tests: real time (no virtual time, so
// requestAnimationFrame runs) and trusted input events. Node 22+ (global fetch and WebSocket).
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser"
].filter(Boolean);

const findChrome = () => CANDIDATES.find(p => fs.existsSync(p)) || null;
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function launch(chromePath) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "phishguard-cdp-"));
  const proc = spawn(chromePath, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--hide-scrollbars=false",
    "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"
  ], { stdio: "ignore" });

  // Chrome writes the chosen port to DevToolsActivePort in the profile.
  let port;
  for (let i = 0; i < 100 && !port; i++) {
    try { port = fs.readFileSync(path.join(profile, "DevToolsActivePort"), "utf8").split("\n")[0]; } catch (_) { await sleep(100); }
  }
  if (!port) { proc.kill(); throw new Error("Chrome did not start"); }
  const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const ws = new WebSocket(list.find(t => t.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });

  let id = 0;
  const pending = new Map();
  const errors = [];
  ws.onmessage = ({ data }) => {
    const msg = JSON.parse(data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const n = ++id;
    pending.set(n, msg => (msg.error ? reject(new Error(`${method}: ${msg.error.message}`)) : resolve(msg.result)));
    ws.send(JSON.stringify({ id: n, method, params }));
  });
  await send("Runtime.enable");
  await send("Page.enable");

  const page = {
    errors,
    send,
    async evaluate(expression) {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
      return r.result.value;
    },
    async viewport(width, height) {
      await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
    },
    async goto(url) {
      await send("Page.navigate", { url });
      await page.waitFor("document.readyState === 'complete'");
    },
    async waitFor(expression, timeout = 3000) {
      const end = Date.now() + timeout;
      while (Date.now() < end) {
        if (await page.evaluate(`!!(${expression})`)) return;
        await sleep(30);
      }
      throw new Error(`Timed out waiting for: ${expression}`);
    },
    // Trusted input, as a real user would produce it.
    async click(x, y) {
      for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
        await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1, pointerType: "mouse" });
      }
    },
    async wheel(x, y, deltaY) {
      await send("Input.dispatchMouseEvent", { type: "mouseWheel", x, y, deltaX: 0, deltaY });
    },
    async key(key, code = key, keyCode = 0) {
      await send("Input.dispatchKeyEvent", { type: "keyDown", key, code, windowsVirtualKeyCode: keyCode });
      await send("Input.dispatchKeyEvent", { type: "keyUp", key, code, windowsVirtualKeyCode: keyCode });
    },
    async frames(n = 3) {
      await page.evaluate(`new Promise(r => { let i = ${n}; const f = () => (--i ? requestAnimationFrame(f) : r()); requestAnimationFrame(f); })`);
    },
    async close() {
      try { ws.close(); } catch (_) {}
      proc.kill();
      await sleep(300);
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) {}
    }
  };
  return page;
}

module.exports = { findChrome, launch, sleep };
