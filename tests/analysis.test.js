// Run with: node --test "tests/*.test.js"
// End-to-end pipeline without Chrome: detector.js + context.js + analysis.js + the background.js
// handler, with only the backend's HTTP response mocked.
const test = require("node:test");
const assert = require("node:assert/strict");
const detector = require("../detector.js");
const context = require("../context.js");
const { analyzeOpenEmail } = require("../analysis.js");
const { createAnalyzeHandler } = require("../background.js");

const GMAIL = { id: "ext", tab: { id: 1 }, frameId: 0, url: "https://mail.google.com/mail/u/0/" };
const RECENT = [
  { senders: ["news@shop.example"], subject: "Weekly deals", snippet: "Save on things" },
  { senders: ["alex@colleague.example"], subject: "Team lunch", snippet: "Friday?" }
];
// Rules: sensitive wording (25) + 1 link (8) = 33. Context: unknown sender (8) + unsupported
// invoice claim (12) = 20. Local baseline L = 53, inside the AI band; no strong evidence.
const INVOICE = {
  subject: "Invoice overdue",
  sender: "billing@acct-notice.example",
  body: "Your invoice is past due. Please review the payment details at our portal today.",
  links: ["https://acct-notice.example/invoice"],
  recentEmails: RECENT
};

const jsonResponse = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });

// Routes analysis.js messages through the real worker handler; only backend fetch is mocked.
function pipeline({ respond, enabled = true, permitted = true } = {}) {
  const backendCalls = [];
  const messages = [];
  const handle = createAnalyzeHandler({
    extensionId: "ext",
    fetchImpl: async (url, init) => { backendCalls.push(JSON.parse(init.body)); return respond(); },
    isEnabled: async () => enabled,
    hasPermission: async () => permitted
  });
  const sendMessage = msg => { messages.push(msg); return handle(msg, GMAIL); };
  return { backendCalls, messages, sendMessage };
}

const local = () => context.applyContext(detector.analyzeEmail(INVOICE), context.analyzeContext(INVOICE, RECENT));

test("fixture: local baseline is 53 from rules 33 + context 20", () => {
  const expected = local();
  assert.equal(expected.score, 53);
  assert.equal(detector.analyzeEmail(INVOICE).score, 33);
  assert.equal(expected.context.score, 20);
});

test("AI off: no message is sent and the result equals today's local result", async () => {
  const { messages, sendMessage } = pipeline({ respond: () => jsonResponse({ score: 0, reasons: [] }) });
  const result = await analyzeOpenEmail(INVOICE, { detector, context, aiEnabled: false, sendMessage });
  assert.equal(messages.length, 0);
  const expected = local();
  for (const key of ["score", "verdict", "reasons", "urlCount", "context"]) assert.deepEqual(result[key], expected[key], key);
  assert.deepEqual(result.ai, { status: "skipped", score: null, reasons: [], reason: "disabled" });
});

test("AI on: blended against L once, context reasons once, inbox rows never sent", async () => {
  const { backendCalls, sendMessage } = pipeline({ respond: () => jsonResponse({ score: 91, reasons: ["Pressure to pay an unknown invoice"] }) });
  const result = await analyzeOpenEmail(INVOICE, { detector, context, aiEnabled: true, sendMessage });
  assert.equal(result.ai.status, "ok");
  assert.equal(result.localScore, 53);
  assert.equal(result.ruleScore, 33);
  assert.equal(result.contextScore, 20);
  assert.equal(result.score, 72); // round(0.5*53 + 0.5*91); context is not added again
  for (const reason of result.context.reasons) {
    assert.equal(result.reasons.filter(r => r === reason).length, 1, reason);
  }
  assert.ok(result.reasons.includes("AI: Pressure to pay an unknown invoice"));

  assert.equal(backendCalls.length, 1);
  const sent = backendCalls[0];
  assert.deepEqual(Object.keys(sent.email).sort(), ["body", "links", "sender", "subject"]);
  assert.deepEqual(sent.context, { score: 20, reasons: result.context.reasons });
  assert.ok(!JSON.stringify(sent).includes("Weekly deals"), "inbox history is not transmitted");
});

for (const [name, setup, reason] of [
  ["backend HTTP failure", { respond: () => jsonResponse({ error: "AI analysis failed." }, 502) }, "http_error"],
  ["malformed backend output", { respond: () => jsonResponse({ score: "very", reasons: [] }) }, "http_error"],
  ["missing backend", { respond: () => { throw new TypeError("Failed to fetch"); } }, "http_error"],
  ["consent revoked in storage", { enabled: false, respond: () => jsonResponse({ score: 0, reasons: [] }) }, "http_error"],
  ["permission removed", { permitted: false, respond: () => jsonResponse({ score: 0, reasons: [] }) }, "http_error"]
]) {
  test(`${name}: local score and findings survive with ai.status "error"`, async () => {
    const { backendCalls, sendMessage } = pipeline(setup);
    const result = await analyzeOpenEmail(INVOICE, { detector, context, aiEnabled: true, sendMessage });
    const expected = local();
    assert.equal(result.score, expected.score);
    assert.deepEqual(result.reasons, expected.reasons);
    assert.deepEqual(result.ai, { status: "error", score: null, reasons: [], reason });
    if (setup.enabled === false || setup.permitted === false) assert.equal(backendCalls.length, 0);
  });
}

test("a worker that never replies falls back to the local result after the timeout", async () => {
  const result = await analyzeOpenEmail(INVOICE, {
    detector, context, aiEnabled: true, timeoutMs: 30, sendMessage: () => new Promise(() => {})
  });
  assert.equal(result.score, 53);
  assert.deepEqual(result.ai, { status: "error", score: null, reasons: [], reason: "timeout" });
});

test("an unreachable worker (extension reloaded) falls back to the local result", async () => {
  const result = await analyzeOpenEmail(INVOICE, {
    detector, context, aiEnabled: true, sendMessage: () => Promise.reject(new Error("Extension context invalidated"))
  });
  assert.equal(result.score, 53);
  assert.equal(result.ai.status, "error");
});

test("aiEnabled must be exactly true to send anything", async () => {
  const { messages, sendMessage } = pipeline({ respond: () => jsonResponse({ score: 0, reasons: [] }) });
  for (const aiEnabled of ["true", 1, undefined, null]) {
    const result = await analyzeOpenEmail(INVOICE, { detector, context, aiEnabled, sendMessage });
    assert.equal(result.ai.reason, "disabled");
  }
  assert.equal(messages.length, 0);
});

test("outside the band (L >= 60) AI isn't asked even when enabled", async () => {
  const phishing = {
    subject: "USPS: Delivery failed",
    sender: "USPS <alerts@usps-redeliver.top>",
    body: "Pay a small fee within 24 hours: http://usps-redeliver.top/pay",
    links: ["http://usps-redeliver.top/pay"],
    recentEmails: RECENT
  };
  const { messages, sendMessage } = pipeline({ respond: () => jsonResponse({ score: 0, reasons: [] }) });
  const result = await analyzeOpenEmail(phishing, { detector, context, aiEnabled: true, sendMessage });
  assert.equal(messages.length, 0);
  assert.equal(result.verdict, "High risk");
  assert.equal(result.ai.reason, "policy");
});
