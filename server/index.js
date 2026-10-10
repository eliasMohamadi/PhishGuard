const express = require("express");

const LIMITS = {
  bodyBytes: "100kb",
  subject: 1000,
  sender: 320,
  body: 50000,
  links: 200,
  link: 2048,
  contextReasons: 20,
  contextReason: 500
};

// PLACEHOLDER: this is NOT real AI analysis. It always returns score 0 so it can
// never raise a rule-based verdict in the extension. Replace in the OpenAI step.
async function placeholderAnalyzer() {
  return {
    score: 0,
    reasons: ["Placeholder response: AI analysis is not implemented yet."]
  };
}

const isPlainObject = value => value !== null && typeof value === "object" && !Array.isArray(value);

function checkString(value, name, max) {
  if (typeof value !== "string") return `${name} must be a string.`;
  if (value.length > max) return `${name} must be at most ${max} characters.`;
  return null;
}

// Returns an error message for the first problem found, or null if the request is valid.
function validateRequest(body) {
  if (!isPlainObject(body)) return "Request body must be a JSON object.";

  const { email, context } = body;
  if (!isPlainObject(email)) return "email must be an object.";

  const fieldError =
    checkString(email.subject, "email.subject", LIMITS.subject) ||
    checkString(email.sender, "email.sender", LIMITS.sender) ||
    checkString(email.body, "email.body", LIMITS.body);
  if (fieldError) return fieldError;

  if (!Array.isArray(email.links)) return "email.links must be an array.";
  if (email.links.length > LIMITS.links) return `email.links must have at most ${LIMITS.links} items.`;
  if (email.links.some(link => typeof link !== "string" || link.length > LIMITS.link)) {
    return `email.links must contain strings of at most ${LIMITS.link} characters.`;
  }

  if (context === undefined || context === null) return null;
  if (!isPlainObject(context)) return "context must be an object when provided.";

  if (context.score !== undefined) {
    if (!Number.isFinite(context.score) || context.score < 0 || context.score > 100) {
      return "context.score must be a number from 0 to 100.";
    }
  }
  if (context.reasons !== undefined) {
    if (!Array.isArray(context.reasons)) return "context.reasons must be an array.";
    if (context.reasons.length > LIMITS.contextReasons) {
      return `context.reasons must have at most ${LIMITS.contextReasons} items.`;
    }
    if (context.reasons.some(r => typeof r !== "string" || r.length > LIMITS.contextReason)) {
      return `context.reasons must contain strings of at most ${LIMITS.contextReason} characters.`;
    }
  }
  return null;
}

// Copy only known fields so unexpected input never reaches the analyzer.
function normalizeRequest({ email, context }) {
  const normalized = {
    email: {
      subject: email.subject,
      sender: email.sender,
      body: email.body,
      links: [...email.links]
    },
    context: null
  };
  if (isPlainObject(context)) {
    normalized.context = { reasons: context.reasons ? [...context.reasons] : [] };
    if (context.score !== undefined) normalized.context.score = context.score;
  }
  return normalized;
}

function createApp({ analyzer = placeholderAnalyzer, logger = console } = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: LIMITS.bodyBytes }));

  app.post("/analyze", async (req, res) => {
    const error = validateRequest(req.body);
    if (error) return res.status(400).json({ error });

    const result = await analyzer(normalizeRequest(req.body));
    res.json({ score: result.score, reasons: result.reasons });
  });

  app.use((req, res) => res.status(404).json({ error: "Not found." }));

  // Never leak stack traces or internal messages to clients.
  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Request body must be valid JSON." });
    if (err.type === "entity.too.large") return res.status(413).json({ error: "Request body is too large." });
    logger.error(err);
    res.status(500).json({ error: "Internal server error." });
  });

  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || "127.0.0.1";
  createApp().listen(port, host, () => {
    console.log(`PhishGuard server (placeholder analyzer) listening on http://${host}:${port}`);
  });
}

module.exports = { createApp, validateRequest, placeholderAnalyzer };
