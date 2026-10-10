// The overlay's analysis pipeline: local rules + inbox context, plus AI review only when the user
// has opted in. All scoring lives in detector.js (includeContextScore: context counted once);
// this file only wires the inputs and routes the AI request through the background worker.
(function (root) {
  "use strict";

  const MESSAGE_TYPE = "PHISHGUARD_AI_ANALYZE";
  // Content-side AI timeout; the worker (7.5 s) and server (7 s) time out first.
  const AI_TIMEOUT_MS = 8000;
  // The real endpoint is fixed in background.js; this value only switches AI on in the detector.
  const WORKER_ENDPOINT = "phishguard-background-worker";

  // A fetch-like adapter for detector.analyzeEmailWithAI that sends the request to the worker.
  // Worker errors become non-ok responses, so the detector falls back to the local result.
  function createWorkerFetch(sendMessage) {
    return (_url, init) => new Promise((resolve, reject) => {
      let payload;
      try {
        payload = JSON.parse(init.body);
      } catch (_) {
        reject(new Error("Invalid AI request"));
        return;
      }
      Promise.resolve()
        .then(() => sendMessage({ type: MESSAGE_TYPE, payload }))
        .then(reply => {
          if (!reply || typeof reply !== "object") throw new Error("No reply from the background worker");
          resolve({ ok: reply.ok === true, status: Number(reply.status) || 0, json: async () => reply.data });
        })
        .catch(() => reject(new Error("Background worker unavailable")));
    });
  }

  async function analyzeOpenEmail(email, { detector, context, aiEnabled = false, sendMessage = null, timeoutMs = AI_TIMEOUT_MS } = {}) {
    if (!detector) throw new Error("Detector not loaded");
    // Inbox rows (email.recentEmails) are used here, locally, and never leave the page: the
    // detector sends only subject, sender, body, links and the context { score, reasons }.
    const findings = context ? context.analyzeContext(email, email.recentEmails) : null;
    const useAI = aiEnabled === true && typeof sendMessage === "function";
    return detector.analyzeEmailWithAI(email, {
      includeContextScore: true,
      context: findings,
      endpoint: useAI ? WORKER_ENDPOINT : null,
      fetchImpl: useAI ? createWorkerFetch(sendMessage) : null,
      timeoutMs
    });
  }

  const api = { analyzeOpenEmail, createWorkerFetch, MESSAGE_TYPE, AI_TIMEOUT_MS };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PhishGuardAnalysis = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
