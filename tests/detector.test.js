// Run with: node --test tests/
// Uses mocked backend responses only; no network or real AI calls.
const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeEmail, analyzeEmailWithAI } = require("../detector.js");

const PHISHING = {
  subject: "Urgent: verify your account",
  sender: "security@paypa1-alerts.com",
  body: "Your account will be suspended. Confirm your password at https://paypal-login.example.com/verify",
  links: []
};
const BENIGN = {
  subject: "Lunch on Friday?",
  sender: "sam@example.com",
  body: "Want to grab lunch on Friday?",
  links: []
};
const ENDPOINT = "https://backend.test/analyze";

function mockFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init, payload: JSON.parse(init.body) });
    return handler(url, init);
  };
  return { fetchImpl, calls };
}

const jsonResponse = (data, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => data
});

test("analyzeEmail is synchronous and keeps its exact output for a phishing email", () => {
  const result = analyzeEmail(PHISHING);
  assert.ok(!(result instanceof Promise));
  assert.deepEqual(result, {
    score: 95,
    verdict: "High risk",
    reasons: [
      "Uses urgent language or threatens an account consequence.",
      "Mentions passwords, financial details, verification codes, or sensitive information.",
      "Contains 1 link; inspect destinations before clicking.",
      "A link uses a URL shortener, punycode, a raw IP address, or a possible brand-lookalike domain.",
      "Link domain differs from the sender's domain; this can be normal, but deserves a check."
    ],
    urlCount: 1
  });
});

test("analyzeEmail keeps its exact output for a benign email", () => {
  assert.deepEqual(analyzeEmail(BENIGN), {
    score: 0,
    verdict: "Lower risk",
    reasons: ["No obvious warning signs were detected by the basic rules."],
    urlCount: 0
  });
});

test("without an endpoint, AI is skipped and the rule result is returned", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 100, reasons: [] }));
  const result = await analyzeEmailWithAI(PHISHING, { fetchImpl });
  assert.equal(calls.length, 0);
  assert.deepEqual(result, {
    ...analyzeEmail(PHISHING),
    ruleScore: 95,
    ai: { status: "skipped", score: null, reasons: [] }
  });
});

test("a successful AI response raises the score and appends prefixed reasons", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 80, reasons: ["Impersonates a colleague"] }));
  const result = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, fetchImpl });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, ENDPOINT);
  assert.equal(calls[0].init.method, "POST");
  assert.deepEqual(calls[0].payload, { email: BENIGN, context: null });
  assert.deepEqual(result, {
    score: 40,
    verdict: "Use caution",
    reasons: [
      "No obvious warning signs were detected by the basic rules.",
      "AI: Impersonates a colleague"
    ],
    urlCount: 0,
    ruleScore: 0,
    ai: { status: "ok", score: 80, reasons: ["Impersonates a colleague"] }
  });
});

test("AI can never lower the rule score", async () => {
  const { fetchImpl } = mockFetch(() => jsonResponse({ score: 0, reasons: ["Looks fine"] }));
  const result = await analyzeEmailWithAI(PHISHING, { endpoint: ENDPOINT, fetchImpl });
  assert.equal(result.score, 95);
  assert.equal(result.verdict, "High risk");
  assert.equal(result.ai.status, "ok");
});

test("AI output is clamped, filtered, capped and truncated", async () => {
  const { fetchImpl } = mockFetch(() => jsonResponse({
    score: 250,
    reasons: ["a", 42, "  ", "b", "c", "d", "e", "f", "x".repeat(500)]
  }));
  const result = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, fetchImpl });
  assert.equal(result.ai.score, 100);
  assert.equal(result.score, 50);
  assert.deepEqual(result.ai.reasons, ["a", "b", "c", "d", "e"]);

  const long = mockFetch(() => jsonResponse({ score: 10, reasons: ["x".repeat(500)] }));
  const truncated = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, fetchImpl: long.fetchImpl });
  assert.equal(truncated.ai.reasons[0].length, 200);
});

for (const [name, handler] of [
  ["HTTP error", () => jsonResponse({ error: "boom" }, 500)],
  ["non-numeric score", () => jsonResponse({ score: "high", reasons: [] })],
  ["malformed JSON", () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError("bad"); } })],
  ["network failure", () => { throw new TypeError("Failed to fetch"); }]
]) {
  test(`${name} falls back to the rule result with ai.status "error"`, async () => {
    const { fetchImpl } = mockFetch(handler);
    const result = await analyzeEmailWithAI(PHISHING, { endpoint: ENDPOINT, fetchImpl });
    assert.deepEqual(result, {
      ...analyzeEmail(PHISHING),
      ruleScore: 95,
      ai: { status: "error", score: null, reasons: [] }
    });
  });
}

test("a slow backend times out and aborts the request", async () => {
  let signal;
  const fetchImpl = (_url, init) => {
    signal = init.signal;
    return new Promise(() => {}); // never resolves
  };
  const result = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, fetchImpl, timeoutMs: 20 });
  assert.equal(result.ai.status, "error");
  assert.equal(result.score, 0);
  assert.equal(signal.aborted, true);
});

test("context findings are normalized to the agreed shape and sent to the backend", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 0, reasons: [] }));
  await analyzeEmailWithAI(BENIGN, {
    endpoint: ENDPOINT,
    fetchImpl,
    context: { score: 140.4, reasons: ["First email from this sender", 7], history: ["dropped"] }
  });
  assert.deepEqual(calls[0].payload.context, { score: 100, reasons: ["First email from this sender"] });

  await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, fetchImpl, context: { reasons: "not an array" } });
  assert.deepEqual(calls[1].payload.context, { reasons: [] });

  await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, fetchImpl, context: "invalid" });
  assert.equal(calls[2].payload.context, null);
});

test("context does not change the rule score by itself", async () => {
  const result = await analyzeEmailWithAI(BENIGN, { context: { score: 100, reasons: ["Suspicious history"] } });
  assert.equal(result.score, 0);
  assert.equal(result.ai.status, "skipped");
});
