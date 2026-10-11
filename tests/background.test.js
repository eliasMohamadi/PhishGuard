// Run with: node --test "tests/*.test.js"
// Drives background.js's handler with mocked storage, permissions and fetch; no network calls.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  createAnalyzeHandler, sanitizePayload, sanitizeResult, MESSAGE_TYPE, ENDPOINT, LIMITS
} = require("../background.js");

const EXTENSION_ID = "phishguard-test-id";
const GMAIL = { id: EXTENSION_ID, tab: { id: 7 }, frameId: 0, url: "https://mail.google.com/mail/u/0/#inbox/abc" };
const EMAIL = {
  subject: "Invoice overdue",
  sender: "billing@acct-notice.example",
  body: "Your invoice is past due.",
  links: ["https://acct-notice.example/invoice"]
};
const PAYLOAD = { email: EMAIL, context: { score: 12, reasons: ["No related recent email was found."] } };
const message = (payload = PAYLOAD) => ({ type: MESSAGE_TYPE, payload });

const jsonResponse = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });

function setup({ enabled = true, permitted = true, respond = () => jsonResponse({ score: 70, reasons: ["Unusual billing request"] }), timeoutMs } = {}) {
  const calls = [];
  const handle = createAnalyzeHandler({
    extensionId: EXTENSION_ID,
    fetchImpl: async (url, init) => {
      calls.push({ url, init, body: JSON.parse(init.body) });
      return respond(url, init);
    },
    isEnabled: async () => (typeof enabled === "function" ? enabled() : enabled),
    hasPermission: async () => (typeof permitted === "function" ? permitted() : permitted),
    timeoutMs
  });
  return { handle, calls };
}

test("forwards a valid request to the fixed endpoint with safe fetch options", async () => {
  const { handle, calls } = setup();
  const reply = await handle(message(), GMAIL);
  assert.deepEqual(reply, { ok: true, status: 200, data: { score: 70, reasons: ["Unusual billing request"] } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:3000/analyze");
  assert.equal(ENDPOINT, "http://127.0.0.1:3000/analyze");
  const { init } = calls[0];
  assert.equal(init.method, "POST");
  assert.equal(init.headers["Content-Type"], "application/json");
  assert.equal(init.credentials, "omit");
  assert.equal(init.cache, "no-store");
  assert.equal(init.redirect, "error");
  assert.ok(init.signal instanceof AbortSignal);
  assert.deepEqual(calls[0].body, PAYLOAD);
});

for (const [name, sender] of [
  ["another extension", { ...GMAIL, id: "someone-else" }],
  ["a non-Gmail page", { ...GMAIL, url: "https://evil.example/mail.google.com/" }],
  ["a Gmail lookalike host", { ...GMAIL, url: "https://mail.google.com.evil.example/" }],
  ["an http Gmail URL", { ...GMAIL, url: "http://mail.google.com/mail" }],
  ["a sub-frame", { ...GMAIL, frameId: 3 }],
  ["an extension page (no tab)", { id: EXTENSION_ID, url: `chrome-extension://${EXTENSION_ID}/popup.html` }],
  ["a missing sender", undefined]
]) {
  test(`rejects messages from ${name} without forwarding`, async () => {
    const { handle, calls } = setup();
    assert.deepEqual(await handle(message(), sender), { ok: false, status: 0, error: "forbidden" });
    assert.equal(calls.length, 0);
  });
}

test("rejects unknown message types and missing payloads", async () => {
  const { handle, calls } = setup();
  assert.equal((await handle({ type: "OTHER", payload: PAYLOAD }, GMAIL)).error, "invalid_request");
  assert.equal((await handle(null, GMAIL)).error, "invalid_request");
  assert.equal((await handle({ type: MESSAGE_TYPE }, GMAIL)).error, "invalid_request");
  assert.equal(calls.length, 0);
});

test("consent is required on every request, and turning it off stops the next one", async () => {
  let enabled = false;
  const { handle, calls } = setup({ enabled: () => enabled });
  assert.deepEqual(await handle(message(), GMAIL), { ok: false, status: 0, error: "not_enabled" });
  enabled = true;
  assert.equal((await handle(message(), GMAIL)).ok, true);
  enabled = false;
  assert.equal((await handle(message(), GMAIL)).error, "not_enabled");
  assert.equal(calls.length, 1);
});

test("only a strict true counts as consent; storage errors count as off", async () => {
  const storageError = () => { throw new Error("storage"); };
  for (const value of ["true", 1, null, undefined, storageError]) {
    const { handle, calls } = setup({ enabled: value === storageError ? value : () => value });
    assert.equal((await handle(message(), GMAIL)).error, "not_enabled");
    assert.equal(calls.length, 0);
  }
});

test("a missing or failing host permission blocks forwarding", async () => {
  for (const permitted of [false, () => { throw new Error("permissions"); }]) {
    const { handle, calls } = setup({ permitted });
    assert.deepEqual(await handle(message(), GMAIL), { ok: false, status: 0, error: "no_permission" });
    assert.equal(calls.length, 0);
  }
});

test("the payload is rebuilt from allow-listed fields only", async () => {
  const { handle, calls } = setup();
  await handle(message({
    email: { ...EMAIL, recentEmails: [{ subject: "private" }], cookie: "x", senderName: "Billing" },
    context: { score: 12, reasons: ["r1", 7, "r2"], findings: [{ type: "sender" }], recentCount: 4, available: true },
    apiKey: "should-not-pass",
    endpoint: "https://evil.example/"
  }), GMAIL);
  assert.deepEqual(calls[0].body, {
    email: EMAIL,
    context: { score: 12, reasons: ["r1", "r2"] }
  });
  assert.equal(calls[0].url, ENDPOINT, "the endpoint can't be chosen by the message");
});

test("links must be http(s), short enough, and are capped", () => {
  const links = ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "mailto:a@b.c", "ftp://x.example/",
    "not a url", 42, `https://x.example/${"a".repeat(LIMITS.link)}`, "http://ok.example/", "https://ok.example/"];
  assert.deepEqual(sanitizePayload({ email: { ...EMAIL, links } }).email.links, ["http://ok.example/", "https://ok.example/"]);
  const many = Array.from({ length: 80 }, (_, i) => `https://l${i}.example/`);
  assert.equal(sanitizePayload({ email: { ...EMAIL, links: many } }).email.links.length, LIMITS.links);
});

test("size limits: body truncated, oversized subject/sender or request rejected", () => {
  assert.equal(sanitizePayload({ email: { ...EMAIL, body: "x".repeat(60000) } }).email.body.length, LIMITS.body);
  assert.equal(sanitizePayload({ email: { ...EMAIL, subject: "s".repeat(LIMITS.subject + 1) } }), null);
  assert.equal(sanitizePayload({ email: { ...EMAIL, sender: "s".repeat(LIMITS.sender + 1) } }), null);
  // 50 maximum-length links of multi-byte characters exceed the request byte budget.
  const huge = Array.from({ length: 50 }, (_, i) => `https://x${i}.example/${"é".repeat(1000)}`);
  assert.equal(sanitizePayload({ email: { ...EMAIL, links: huge } }), null);
});

test("malformed email or context shapes are rejected; context score out of range is dropped", () => {
  assert.equal(sanitizePayload({ email: { ...EMAIL, body: 5 } }), null);
  assert.equal(sanitizePayload({ email: { ...EMAIL, links: "https://x.example" } }), null);
  assert.equal(sanitizePayload({ email: null }), null);
  assert.equal(sanitizePayload({ email: EMAIL, context: "high" }), null);
  assert.deepEqual(sanitizePayload({ email: EMAIL, context: { score: 140, reasons: "x" } }).context, { reasons: [] });
  assert.equal(sanitizePayload({ email: EMAIL }).context, null);
  const reasons = Array.from({ length: 30 }, () => "r".repeat(900));
  const context = sanitizePayload({ email: EMAIL, context: { reasons } }).context;
  assert.equal(context.reasons.length, LIMITS.contextReasons);
  assert.equal(context.reasons[0].length, LIMITS.contextReason);
});

for (const [name, respond, expected] of [
  ["HTTP 503 (not configured)", () => jsonResponse({ error: "AI analysis is not configured." }, 503), { ok: false, status: 503, error: "http_error" }],
  ["HTTP 502 with provider text", () => jsonResponse({ error: "Gemini said: quota exceeded for key AIza..." }, 502), { ok: false, status: 502, error: "http_error" }],
  ["a network failure", () => { throw new TypeError("Failed to fetch"); }, { ok: false, status: 0, error: "network_error" }],
  ["invalid JSON", () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError("Unexpected token"); } }), { ok: false, status: 0, error: "invalid_response" }],
  ["a non-numeric score", () => jsonResponse({ score: "high", reasons: [] }), { ok: false, status: 0, error: "invalid_response" }],
  ["an out-of-range score", () => jsonResponse({ score: 250, reasons: [] }), { ok: false, status: 0, error: "invalid_response" }],
  ["missing reasons", () => jsonResponse({ score: 40 }), { ok: false, status: 0, error: "invalid_response" }]
]) {
  test(`${name} returns a sanitized error`, async () => {
    const { handle } = setup({ respond });
    const reply = await handle(message(), GMAIL);
    assert.deepEqual(reply, expected);
    assert.ok(!JSON.stringify(reply).includes("Gemini"), "no backend text in the reply");
  });
}

test("valid results are cleaned: rounded score, trimmed and capped reasons", () => {
  assert.deepEqual(sanitizeResult({ score: 61.6, reasons: [" a ", 3, "", "b", "c", "d", "e", "f", "x".repeat(400)], extra: 1 }), {
    score: 62, reasons: ["a", "b", "c", "d", "e"]
  });
  assert.equal(sanitizeResult({ score: 10, reasons: ["y".repeat(400)] }).reasons[0].length, LIMITS.aiReason);
});

test("a stalled backend times out and the request is aborted", async () => {
  let signal;
  const { handle } = setup({
    timeoutMs: 20,
    respond: (_url, init) => { signal = init.signal; return new Promise(() => {}); }
  });
  const started = Date.now();
  assert.deepEqual(await handle(message(), GMAIL), { ok: false, status: 0, error: "timeout" });
  assert.ok(Date.now() - started < 1000);
  assert.equal(signal.aborted, true);
});

test("a body that never finishes reading also times out", async () => {
  const { handle } = setup({ timeoutMs: 20, respond: () => ({ ok: true, status: 200, json: () => new Promise(() => {}) }) });
  assert.equal((await handle(message(), GMAIL)).error, "timeout");
});

test("the worker's timeout is shorter than the content-side AI timeout", () => {
  const { TIMEOUT_MS } = require("../background.js");
  const { AI_TIMEOUT_MS } = require("../analysis.js");
  assert.ok(TIMEOUT_MS < AI_TIMEOUT_MS);
});

test("extension code contains no Gemini credentials or provider access", () => {
  const root = path.join(__dirname, "..");
  const files = ["background.js", "analysis.js", "content.js", "detector.js", "context.js", "overlay.js", "popup.js", "popup.html", "manifest.json"];
  for (const file of files) {
    const text = fs.readFileSync(path.join(root, file), "utf8");
    assert.doesNotMatch(text, /AIza[0-9A-Za-z_-]{20,}|GEMINI_API_KEY|generativelanguage\.googleapis|@google\/genai/, file);
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  assert.deepEqual(manifest.optional_host_permissions, ["http://127.0.0.1:3000/*"]);
  assert.deepEqual(manifest.host_permissions, ["https://mail.google.com/*"], "localhost access is optional, not granted at install");
});
