// MV3 service worker: forwards opted-in AI review requests from the Gmail content script to the
// local PhishGuard backend, which holds the Gemini key (server/.env). No key or provider access
// exists in extension code. The handler is a pure function so Node tests can drive it.
(function (root) {
  "use strict";

  const MESSAGE_TYPE = "PHISHGUARD_AI_ANALYZE";
  const ENDPOINT = "http://127.0.0.1:3000/analyze";
  const ORIGIN_PATTERN = "http://127.0.0.1:3000/*";
  const SETTING_KEY = "aiReviewEnabled";
  // server 7000 ms < worker 7500 ms < content-side 8000 ms, so each layer reports its own failure.
  const TIMEOUT_MS = 7500;

  // Matches the backend's contract. The body is capped at what the backend shows the model
  // (12 000 characters) and links at the 50 it uses: nothing beyond that is sent.
  const LIMITS = {
    subject: 1000,
    sender: 320,
    body: 12000,
    links: 50,
    link: 2048,
    contextReasons: 20,
    contextReason: 500,
    requestBytes: 90000, // under the backend's 100 kb JSON limit
    aiReasons: 5,
    aiReason: 200
  };

  const isPlainObject = v => v !== null && typeof v === "object" && !Array.isArray(v);
  const fail = (error, status = 0) => ({ ok: false, status, error });

  // Only this extension's content script, in Gmail's top frame, may ask for AI review.
  function isGmailContentScript(sender, extensionId) {
    if (!isPlainObject(sender) || !extensionId || sender.id !== extensionId) return false;
    if (!isPlainObject(sender.tab) || sender.frameId !== 0 || typeof sender.url !== "string") return false;
    try {
      return new URL(sender.url).origin === "https://mail.google.com";
    } catch (_) {
      return false;
    }
  }

  function isHttpUrl(value) {
    try {
      const { protocol } = new URL(value);
      return protocol === "http:" || protocol === "https:";
    } catch (_) {
      return false;
    }
  }

  // Rebuild the request from known fields only; anything else (recentEmails, findings, extra
  // keys) is dropped. Returns null when the payload doesn't match the contract.
  function sanitizePayload(payload) {
    if (!isPlainObject(payload) || !isPlainObject(payload.email)) return null;
    const { subject, sender, body, links } = payload.email;
    if (typeof subject !== "string" || subject.length > LIMITS.subject) return null;
    if (typeof sender !== "string" || sender.length > LIMITS.sender) return null;
    if (typeof body !== "string" || !Array.isArray(links)) return null;

    const email = {
      subject,
      sender,
      body: body.slice(0, LIMITS.body),
      links: links
        .filter(link => typeof link === "string" && link.length <= LIMITS.link && isHttpUrl(link))
        .slice(0, LIMITS.links)
    };

    let context = null;
    if (payload.context !== undefined && payload.context !== null) {
      if (!isPlainObject(payload.context)) return null;
      const { score, reasons } = payload.context;
      context = {
        reasons: (Array.isArray(reasons) ? reasons : [])
          .filter(r => typeof r === "string")
          .slice(0, LIMITS.contextReasons)
          .map(r => r.slice(0, LIMITS.contextReason))
      };
      if (Number.isFinite(score) && score >= 0 && score <= 100) context.score = score;
    }

    const request = { email, context };
    if (new TextEncoder().encode(JSON.stringify(request)).length > LIMITS.requestBytes) return null;
    return request;
  }

  // Backend output is checked again here; only a score and short reasons pass through.
  function sanitizeResult(data) {
    if (!isPlainObject(data) || !Number.isFinite(data.score) || data.score < 0 || data.score > 100) return null;
    if (!Array.isArray(data.reasons)) return null;
    return {
      score: Math.round(data.score),
      reasons: data.reasons
        .filter(r => typeof r === "string" && r.trim())
        .slice(0, LIMITS.aiReasons)
        .map(r => r.trim().slice(0, LIMITS.aiReason))
    };
  }

  // Replies are always { ok: true, status: 200, data } or { ok: false, status, error } with a fixed
  // error code; backend bodies, provider text and email content never appear in an error.
  function createAnalyzeHandler({ extensionId, fetchImpl, isEnabled, hasPermission, timeoutMs = TIMEOUT_MS }) {
    return async function handleAnalyzeMessage(message, sender) {
      if (!isGmailContentScript(sender, extensionId)) return fail("forbidden");
      if (!isPlainObject(message) || message.type !== MESSAGE_TYPE) return fail("invalid_request");

      // Consent is checked on every request, so turning AI off stops the next one.
      let enabled = false;
      try { enabled = (await isEnabled()) === true; } catch (_) { /* treat as off */ }
      if (!enabled) return fail("not_enabled");
      let permitted = false;
      try { permitted = (await hasPermission()) === true; } catch (_) { /* treat as denied */ }
      if (!permitted) return fail("no_permission");

      const request = sanitizePayload(message.payload);
      if (!request) return fail("invalid_request");

      const controller = new AbortController();
      let timer;
      const timeout = new Promise(resolve => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(fail("timeout"));
        }, timeoutMs);
      });
      const call = (async () => {
        let response;
        try {
          response = await fetchImpl(ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
            credentials: "omit",
            cache: "no-store",
            redirect: "error",
            signal: controller.signal
          });
        } catch (_) {
          return controller.signal.aborted ? fail("timeout") : fail("network_error");
        }
        if (!response?.ok) return fail("http_error", Number(response?.status) || 0);
        let data;
        try {
          data = await response.json();
        } catch (_) {
          return controller.signal.aborted ? fail("timeout") : fail("invalid_response");
        }
        const result = sanitizeResult(data);
        return result ? { ok: true, status: 200, data: result } : fail("invalid_response");
      })();

      try {
        return await Promise.race([call, timeout]);
      } finally {
        clearTimeout(timer);
      }
    };
  }

  const api = {
    createAnalyzeHandler, sanitizePayload, sanitizeResult, isGmailContentScript,
    MESSAGE_TYPE, ENDPOINT, ORIGIN_PATTERN, SETTING_KEY, TIMEOUT_MS, LIMITS
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;

  const chrome = root.chrome;
  if (chrome?.runtime?.onMessage) {
    const handle = createAnalyzeHandler({
      extensionId: chrome.runtime.id,
      fetchImpl: (...args) => root.fetch(...args),
      isEnabled: async () => (await chrome.storage.local.get(SETTING_KEY))[SETTING_KEY] === true,
      hasPermission: () => chrome.permissions.contains({ origins: [ORIGIN_PATTERN] })
    });

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message?.type !== MESSAGE_TYPE) return false;
      handle(message, sender).then(sendResponse, () => sendResponse(fail("internal_error")));
      return true; // reply asynchronously
    });

    // If the user revokes the localhost permission (e.g. in chrome://extensions), AI turns off too.
    chrome.permissions?.onRemoved?.addListener(({ origins = [] }) => {
      if (origins.includes(ORIGIN_PATTERN)) chrome.storage.local.set({ [SETTING_KEY]: false });
    });
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
