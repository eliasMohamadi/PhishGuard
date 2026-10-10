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
// Existing wrapper tests use fixtures scoring 0 and 95 (outside the default uncertainty band),
// so they opt into always calling AI to keep exercising the request/response handling.
const ALWAYS_CALL_AI = { uncertainMin: 0, verifyHighRisk: true };

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
  const result = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl });
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
  const result = await analyzeEmailWithAI(PHISHING, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl });
  assert.equal(result.score, 95);
  assert.equal(result.verdict, "High risk");
  assert.equal(result.ai.status, "ok");
});

test("AI output is clamped, filtered, capped and truncated", async () => {
  const { fetchImpl } = mockFetch(() => jsonResponse({
    score: 250,
    reasons: ["a", 42, "  ", "b", "c", "d", "e", "f", "x".repeat(500)]
  }));
  const result = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl });
  assert.equal(result.ai.score, 100);
  assert.equal(result.score, 50);
  assert.deepEqual(result.ai.reasons, ["a", "b", "c", "d", "e"]);

  const long = mockFetch(() => jsonResponse({ score: 10, reasons: ["x".repeat(500)] }));
  const truncated = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl: long.fetchImpl });
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
    const result = await analyzeEmailWithAI(PHISHING, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl });
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
  const result = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl, timeoutMs: 20 });
  assert.equal(result.ai.status, "error");
  assert.equal(result.score, 0);
  assert.equal(signal.aborted, true);
});

test("context findings are normalized to the agreed shape and sent to the backend", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 0, reasons: [] }));
  await analyzeEmailWithAI(BENIGN, {
    endpoint: ENDPOINT,
    policy: ALWAYS_CALL_AI,
    fetchImpl,
    context: { score: 140.4, reasons: ["First email from this sender", 7], history: ["dropped"] }
  });
  assert.deepEqual(calls[0].payload.context, { score: 100, reasons: ["First email from this sender"] });

  await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl, context: { reasons: "not an array" } });
  assert.deepEqual(calls[1].payload.context, { reasons: [] });

  await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, policy: ALWAYS_CALL_AI, fetchImpl, context: "invalid" });
  assert.equal(calls[2].payload.context, null);
});

test("context does not change the rule score by itself", async () => {
  const result = await analyzeEmailWithAI(BENIGN, { context: { score: 100, reasons: ["Suspicious history"] } });
  assert.equal(result.score, 0);
  assert.equal(result.ai.status, "skipped");
});

// --- Selective AI calling and score combination ---
const { shouldCallAI, combineScores, DEFAULT_AI_POLICY } = require("../detector.js");

// Generic wording only (urgency + sensitive terms, no links): rule score 47, no strong evidence.
const WORDING_ONLY = {
  subject: "Urgent: password reset required",
  sender: "it-helpdesk@company.example",
  body: "Please reset your password today using the internal portal.",
  links: []
};
// Shortener link from an unrelated sender: rule score 48 with strong technical evidence.
const SHORTENER = {
  subject: "Your order",
  sender: "orders@shop.example",
  body: "Track it here: https://bit.ly/abc123",
  links: []
};

test("fixtures sit inside the default uncertainty band", () => {
  assert.equal(analyzeEmail(WORDING_ONLY).score, 47);
  assert.equal(analyzeEmail(SHORTENER).score, 48);
});

test("default uncertainty band boundaries are 20 and 59", () => {
  assert.equal(shouldCallAI(0), false);
  assert.equal(shouldCallAI(19), false);
  assert.equal(shouldCallAI(20), true);
  assert.equal(shouldCallAI(59), true);
  assert.equal(shouldCallAI(60), false);
  assert.equal(shouldCallAI(100), false);
  assert.equal(shouldCallAI(60, { ...DEFAULT_AI_POLICY, verifyHighRisk: true }), true);
});

test("default policy is frozen so callers must override per call", () => {
  assert.ok(Object.isFrozen(DEFAULT_AI_POLICY));
});

test("below the band, AI is skipped without a network call", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 90, reasons: ["x"] }));
  const result = await analyzeEmailWithAI(BENIGN, { endpoint: ENDPOINT, fetchImpl });
  assert.equal(calls.length, 0);
  assert.deepEqual(result, { ...analyzeEmail(BENIGN), ruleScore: 0, ai: { status: "skipped", score: null, reasons: [] } });
});

test("high-risk emails warn immediately and skip AI by default", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 0, reasons: [] }));
  const result = await analyzeEmailWithAI(PHISHING, { endpoint: ENDPOINT, fetchImpl });
  assert.equal(calls.length, 0);
  assert.equal(result.score, 95);
  assert.equal(result.verdict, "High risk");
  assert.equal(result.ai.status, "skipped");
});

test("emails inside the band call AI once", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 47, reasons: [] }));
  const result = await analyzeEmailWithAI(WORDING_ONLY, { endpoint: ENDPOINT, fetchImpl });
  assert.equal(calls.length, 1);
  assert.equal(result.ai.status, "ok");
});

test("policy overrides move the band per call", async () => {
  const { fetchImpl, calls } = mockFetch(() => jsonResponse({ score: 47, reasons: [] }));
  const result = await analyzeEmailWithAI(WORDING_ONLY, { endpoint: ENDPOINT, fetchImpl, policy: { uncertainMin: 50 } });
  assert.equal(calls.length, 0);
  assert.equal(result.ai.status, "skipped");
});

test("AI can correct a wording-only false positive", async () => {
  const { fetchImpl } = mockFetch(() => jsonResponse({ score: 0, reasons: ["Routine internal IT notice"] }));
  const result = await analyzeEmailWithAI(WORDING_ONLY, { endpoint: ENDPOINT, fetchImpl });
  // blend = round(0.5*47 + 0.5*0) = 24; floor = 47 - 25 = 22
  assert.equal(result.score, 24);
  assert.equal(result.verdict, "Lower risk");
  assert.equal(result.ruleScore, 47);
  assert.ok(result.reasons.includes("AI: Routine internal IT notice"));
});

test("AI cannot lower the score when strong link evidence is present", async () => {
  const { fetchImpl } = mockFetch(() => jsonResponse({ score: 0, reasons: ["Looks like a normal order"] }));
  const result = await analyzeEmailWithAI(SHORTENER, { endpoint: ENDPOINT, fetchImpl });
  assert.equal(result.score, 48);
  assert.equal(result.verdict, "Use caution");
});

test("AI can raise the score with or without strong evidence", async () => {
  const { fetchImpl } = mockFetch(() => jsonResponse({ score: 100, reasons: [] }));
  assert.equal((await analyzeEmailWithAI(WORDING_ONLY, { endpoint: ENDPOINT, fetchImpl })).score, 74);
  assert.equal((await analyzeEmailWithAI(SHORTENER, { endpoint: ENDPOINT, fetchImpl })).score, 74);
});

test("combineScores caps how far AI can lower a wording-only score", () => {
  // blend = 33, floor = 65 - 25 = 40
  assert.equal(combineScores(65, 0, false), 40);
  assert.equal(combineScores(65, 0, true), 65);
  assert.equal(combineScores(30, 30, false), 30);
  assert.equal(combineScores(10, 0, false), 5);
});

test("combineScores respects policy weight and reduction settings", () => {
  const rulesOnly = { ...DEFAULT_AI_POLICY, aiWeight: 0 };
  assert.equal(combineScores(47, 100, false, rulesOnly), 47);
  assert.equal(combineScores(47, 0, false, rulesOnly), 47);
  const noReduction = { ...DEFAULT_AI_POLICY, maxAiReduction: 0 };
  assert.equal(combineScores(47, 0, false, noReduction), 47);
  const fullTrust = { ...DEFAULT_AI_POLICY, aiWeight: 1, maxAiReduction: 100 };
  assert.equal(combineScores(47, 0, false, fullTrust), 0);
  assert.equal(combineScores(47, 0, true, fullTrust), 47);
});

test("analyzeEmail does not expose internal signals", () => {
  assert.equal("strongEvidence" in analyzeEmail(SHORTENER), false);
});
