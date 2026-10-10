// Run with: npm test (from server/)
// Starts the app on an ephemeral 127.0.0.1 port only; no external network or AI calls.
const test = require("node:test");
const assert = require("node:assert/strict");
const { createApp } = require("./index.js");

const VALID_EMAIL = {
  subject: "Urgent: verify your account",
  sender: "security@paypa1-alerts.com",
  body: "Confirm your password at https://paypal-login.example.com/verify",
  links: ["https://paypal-login.example.com/verify"]
};

async function startServer(options) {
  const server = createApp({ logger: { error() {} }, ...options }).listen(0, "127.0.0.1");
  await new Promise(resolve => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, close: () => new Promise(resolve => server.close(resolve)) };
}

async function post(base, body, { raw = false, path = "/analyze" } = {}) {
  const response = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: raw ? body : JSON.stringify(body)
  });
  return { status: response.status, body: await response.json() };
}

test("requiring the module does not start a server", () => {
  const mod = require("./index.js");
  assert.equal(typeof mod.createApp, "function");
});

test("valid request returns the labelled placeholder response", async t => {
  const { base, close } = await startServer();
  t.after(close);
  const res = await post(base, { email: VALID_EMAIL });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, {
    score: 0,
    reasons: ["Placeholder response: AI analysis is not implemented yet."]
  });
});

test("analyzer receives only normalized known fields", async t => {
  const calls = [];
  const analyzer = async input => {
    calls.push(input);
    return { score: 42, reasons: ["mocked"] };
  };
  const { base, close } = await startServer({ analyzer });
  t.after(close);

  const res = await post(base, {
    email: { ...VALID_EMAIL, extra: "dropped" },
    context: { score: 30, reasons: ["First email from this sender"], history: ["dropped"] },
    unexpected: true
  });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { score: 42, reasons: ["mocked"] });
  assert.deepEqual(calls, [{
    email: VALID_EMAIL,
    context: { score: 30, reasons: ["First email from this sender"] }
  }]);
});

test("context is optional and may be null or partial", async t => {
  const calls = [];
  const analyzer = async input => {
    calls.push(input.context);
    return { score: 0, reasons: [] };
  };
  const { base, close } = await startServer({ analyzer });
  t.after(close);

  for (const context of [undefined, null, {}, { score: 0 }, { reasons: [] }]) {
    const res = await post(base, { email: VALID_EMAIL, context });
    assert.equal(res.status, 200, `context ${JSON.stringify(context)}`);
  }
  assert.deepEqual(calls, [null, null, { reasons: [] }, { reasons: [], score: 0 }, { reasons: [] }]);
});

const invalidCases = [
  ["non-object body", [1, 2, 3], "Request body must be a JSON object."],
  ["missing email", {}, "email must be an object."],
  ["email is an array", { email: [] }, "email must be an object."],
  ["missing subject", { email: { ...VALID_EMAIL, subject: undefined } }, "email.subject must be a string."],
  ["numeric sender", { email: { ...VALID_EMAIL, sender: 5 } }, "email.sender must be a string."],
  ["body too long", { email: { ...VALID_EMAIL, body: "x".repeat(50001) } }, "email.body must be at most 50000 characters."],
  ["links not an array", { email: { ...VALID_EMAIL, links: "https://a.test" } }, "email.links must be an array."],
  ["non-string link", { email: { ...VALID_EMAIL, links: [42] } }, "email.links must contain strings of at most 2048 characters."],
  ["context is a string", { email: VALID_EMAIL, context: "bad" }, "context must be an object when provided."],
  ["context score out of range", { email: VALID_EMAIL, context: { score: 101 } }, "context.score must be a number from 0 to 100."],
  ["context score not a number", { email: VALID_EMAIL, context: { score: "50" } }, "context.score must be a number from 0 to 100."],
  ["context reasons not an array", { email: VALID_EMAIL, context: { reasons: "x" } }, "context.reasons must be an array."],
  ["non-string context reason", { email: VALID_EMAIL, context: { reasons: [1] } }, "context.reasons must contain strings of at most 500 characters."]
];

test("invalid requests are rejected with 400 and never reach the analyzer", async t => {
  let called = false;
  const { base, close } = await startServer({ analyzer: async () => { called = true; } });
  t.after(close);

  for (const [name, body, error] of invalidCases) {
    const res = await post(base, body);
    assert.equal(res.status, 400, name);
    assert.deepEqual(res.body, { error }, name);
  }
  assert.equal(called, false);
});

test("malformed JSON returns a safe 400", async t => {
  const { base, close } = await startServer();
  t.after(close);
  const res = await post(base, "{not json", { raw: true });
  assert.equal(res.status, 400);
  assert.deepEqual(res.body, { error: "Request body must be valid JSON." });
});

test("oversized payload returns 413", async t => {
  const { base, close } = await startServer();
  t.after(close);
  const res = await post(base, { email: { ...VALID_EMAIL, body: "x".repeat(200 * 1024) } });
  assert.equal(res.status, 413);
  assert.deepEqual(res.body, { error: "Request body is too large." });
});

test("analyzer failures return a generic 500 without leaking details", async t => {
  const logged = [];
  const analyzer = async () => { throw new Error("secret internal detail sk-test"); };
  const { base, close } = await startServer({ analyzer, logger: { error: e => logged.push(e) } });
  t.after(close);

  const res = await post(base, { email: VALID_EMAIL });
  assert.equal(res.status, 500);
  assert.deepEqual(res.body, { error: "Internal server error." });
  assert.equal(logged.length, 1);
});

test("unknown routes return a JSON 404", async t => {
  const { base, close } = await startServer();
  t.after(close);
  const res = await post(base, { email: VALID_EMAIL }, { path: "/nope" });
  assert.equal(res.status, 404);
  assert.deepEqual(res.body, { error: "Not found." });
});
