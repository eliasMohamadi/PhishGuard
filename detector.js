// Lightweight local heuristics for the hackathon MVP.
// This is not a trained model and cannot guarantee that a message is safe.
(function (root) {
  "use strict";

  const URGENCY = [
    /\bact now\b/i, /\bimmediately\b/i, /\burgent\b/i, /\bwithin 24 hours\b/i,
    /\baccount (?:will be|has been) (?:suspended|locked|closed)\b/i,
    /\bfinal warning\b/i, /\bverify (?:your )?(?:account|identity)\b/i,
    /\bavoid (?:suspension|closure|termination)\b/i
  ];
  const SENSITIVE = [
    /\bpassword\b/i, /\bsocial security\b/i, /\bssn\b/i,
    /\bcredit card\b/i, /\bbank account\b/i, /\bone[- ]time code\b/i,
    /\bwire transfer\b/i, /\bpayment details\b/i, /\bgift cards?\b/i
  ];
  // Brand name -> domains the brand legitimately sends links from.
  const BRANDS = {
    usps: ["usps.com"], fedex: ["fedex.com"], ups: ["ups.com"], irs: ["irs.gov"],
    microsoft: ["microsoft.com", "live.com", "office.com"],
    google: ["google.com", "youtube.com"], apple: ["apple.com", "icloud.com"],
    paypal: ["paypal.com"], netflix: ["netflix.com"]
  };
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl", "ow.ly", "cutt.ly"];

  function extractUrls(text) {
    const matches = String(text || "").match(/https?:\/\/[^\s<>"')\]]+/gi) || [];
    return [...new Set(matches.map(s => s.replace(/[.,!?;:]+$/, "")))];
  }

  function getHostname(url) {
    try { return new URL(url).hostname.toLowerCase().replace(/^www\./, ""); }
    catch (_) { return ""; }
  }

  // True when host is domain itself or one of its subdomains.
  function isOnDomain(host, domain) {
    return host === domain || host.endsWith(`.${domain}`);
  }

  // Rough "registrable domain" (last two labels) so mail.paypal.com matches paypal.com.
  function baseDomain(host) {
    return host.split(".").slice(-2).join(".");
  }

  function isSuspiciousHost(host, mentionedBrands) {
    if (!host) return true;
    if (host.includes("xn--")) return true;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
    if (SHORTENERS.some(s => isOnDomain(host, s))) return true;
    // Brand lookalike: host contains a brand name mentioned in the email but isn't that brand's domain.
    return mentionedBrands.some(brand =>
      host.includes(brand) && !BRANDS[brand].some(d => isOnDomain(host, d)));
  }

  function analyzeEmail(input) {
    const subject = String(input?.subject || "");
    const sender = String(input?.sender || "");
    const body = String(input?.body || "");
    const combined = `${subject}\n${sender}\n${body}`;
    const reasons = [];
    let score = 0;

    if (URGENCY.some(rx => rx.test(combined))) {
      score += 22;
      reasons.push("Uses urgent language or threatens an account consequence.");
    }
    if (SENSITIVE.some(rx => rx.test(combined))) {
      score += 25;
      reasons.push("Mentions passwords, financial details, verification codes, or sensitive information.");
    }

    const links = Array.isArray(input?.links) ? input.links : [];
    const urls = [...new Set([...links, ...extractUrls(body)])];
    if (urls.length > 0) {
      score += 8;
      reasons.push(`Contains ${urls.length} link${urls.length === 1 ? "" : "s"}; inspect destinations before clicking.`);
    }

    const mentionedBrands = Object.keys(BRANDS)
      .filter(brand => new RegExp(`\\b${brand}\\b`, "i").test(combined));
    if (urls.some(url => isSuspiciousHost(getHostname(url), mentionedBrands))) {
      score += 30;
      reasons.push("A link uses a URL shortener, punycode, a raw IP address, or a possible brand-lookalike domain.");
    }

    const senderMatch = sender.match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
    const senderBase = senderMatch ? baseDomain(senderMatch[1].toLowerCase()) : "";
    if (senderBase && urls.some(url => {
      const host = getHostname(url);
      return host && !isOnDomain(host, senderBase);
    })) {
      score += 10;
      reasons.push("Link domain differs from the sender's domain; this can be normal, but deserves a check.");
    }
    if (!reasons.length) reasons.push("No obvious warning signs were detected by the basic rules.");

    score = Math.min(100, score);
    return { score, verdict: verdictFor(score), reasons, urlCount: urls.length };
  }

  function verdictFor(score) {
    return score >= 60 ? "High risk" : score >= 30 ? "Use caution" : "Lower risk";
  }

  const AI_MAX_REASONS = 5;
  const AI_MAX_REASON_LENGTH = 200;

  function clampScore(n) {
    return Math.max(0, Math.min(100, Math.round(n)));
  }

  // Keep only the agreed ContextFindings shape: { score?: 0-100, reasons: string[] }.
  function normalizeContext(context) {
    if (!context || typeof context !== "object") return null;
    const findings = {
      reasons: Array.isArray(context.reasons) ? context.reasons.filter(r => typeof r === "string") : []
    };
    if (Number.isFinite(context.score)) findings.score = clampScore(context.score);
    return findings;
  }

  // Backend output is untrusted (the email itself may try to steer the model), so validate and cap it.
  function parseAiResponse(data) {
    if (!Number.isFinite(data?.score)) throw new Error("Invalid AI response");
    const reasons = (Array.isArray(data.reasons) ? data.reasons : [])
      .filter(r => typeof r === "string" && r.trim())
      .slice(0, AI_MAX_REASONS)
      .map(r => r.trim().slice(0, AI_MAX_REASON_LENGTH));
    return { score: clampScore(data.score), reasons };
  }

  // Rule-based result optionally combined with a backend AI verdict. Never throws:
  // any AI failure falls back to the rule result with ai.status "skipped" or "error".
  async function analyzeEmailWithAI(email, options = {}) {
    const {
      context = null,
      endpoint = null,
      fetchImpl = typeof root.fetch === "function" ? (...args) => root.fetch(...args) : null,
      timeoutMs = 8000
    } = options;
    const rules = analyzeEmail(email);
    const fallback = status => ({ ...rules, ruleScore: rules.score, ai: { status, score: null, reasons: [] } });
    if (!endpoint || typeof fetchImpl !== "function") return fallback("skipped");

    const payload = {
      email: {
        subject: String(email?.subject || ""),
        sender: String(email?.sender || ""),
        body: String(email?.body || ""),
        links: Array.isArray(email?.links) ? email.links.filter(l => typeof l === "string") : []
      },
      context: normalizeContext(context)
    };

    const controller = typeof AbortController === "function" ? new AbortController() : null;
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller?.abort();
        reject(new Error("AI analysis timed out"));
      }, timeoutMs);
    });

    try {
      const request = (async () => {
        const response = await fetchImpl(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller?.signal
        });
        if (!response?.ok) throw new Error(`AI backend returned ${response?.status}`);
        return parseAiResponse(await response.json());
      })();
      request.catch(() => {}); // a late failure after a timeout is already handled
      const ai = await Promise.race([request, timeout]);
      // AI can raise the rule score but never lower it.
      const score = Math.max(rules.score, Math.round((rules.score + ai.score) / 2));
      return {
        score,
        verdict: verdictFor(score),
        reasons: [...rules.reasons, ...ai.reasons.map(r => `AI: ${r}`)],
        urlCount: rules.urlCount,
        ruleScore: rules.score,
        ai: { status: "ok", score: ai.score, reasons: ai.reasons }
      };
    } catch (_) {
      return fallback("error");
    } finally {
      clearTimeout(timer);
    }
  }

  const api = { analyzeEmail, analyzeEmailWithAI, extractUrls };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PhishGuardDetector = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
