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
  const NO_SIGNS_REASON = "No obvious warning signs were detected by the basic rules.";
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

  // Full rule evaluation, including internal signals that are not part of analyzeEmail's public result.
  function evaluateRules(input) {
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
    // Technical link evidence is "strong": AI may not talk the score down when it fires.
    const strongEvidence = urls.some(url => isSuspiciousHost(getHostname(url), mentionedBrands));
    if (strongEvidence) {
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
    if (!reasons.length) reasons.push(NO_SIGNS_REASON);

    score = Math.min(100, score);
    return { score, verdict: verdictFor(score), reasons, urlCount: urls.length, strongEvidence };
  }

  function analyzeEmail(input) {
    const { strongEvidence, ...result } = evaluateRules(input);
    return result;
  }

  function verdictFor(score) {
    return score >= 60 ? "High risk" : score >= 30 ? "Use caution" : "Lower risk";
  }

  // When to ask the backend AI, and how much its score may move the rule score.
  // These are starting values, not tuned results; override per call via options.policy.
  const DEFAULT_AI_POLICY = Object.freeze({
    uncertainMin: 20,      // rule scores below this skip AI (likely benign; saves cost and latency)
    uncertainMax: 59,      // rule scores above this are high risk and warn immediately
    verifyHighRisk: false, // true = also ask AI about high-risk emails
    aiWeight: 0.7,         // share of the AI score in the blend (0 = local only, 1 = AI only)
    maxAiReduction: 25     // most points AI may subtract when there is no strong evidence
  });

  function resolvePolicy(overrides) {
    return { ...DEFAULT_AI_POLICY, ...(overrides && typeof overrides === "object" ? overrides : {}) };
  }

  function shouldCallAI(ruleScore, policy = DEFAULT_AI_POLICY) {
    if (ruleScore < policy.uncertainMin) return false;
    if (ruleScore > policy.uncertainMax) return Boolean(policy.verifyHighRisk);
    return true;
  }

  // Blend a local score (R, or L with includeContextScore) with the AI score. With strong evidence
  // AI can only raise the score; otherwise it may lower it (to correct generic-wording false
  // positives) by at most maxAiReduction.
  function combineScores(ruleScore, aiScore, strongEvidence, policy = DEFAULT_AI_POLICY) {
    const blended = Math.round((1 - policy.aiWeight) * ruleScore + policy.aiWeight * aiScore);
    const floor = strongEvidence ? ruleScore : ruleScore - policy.maxAiReduction;
    return clampScore(Math.max(blended, floor));
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

  // Local baseline L = min(100, R + C): rule score R plus the context adjustment C, each counted
  // once. Mirrors context.js applyContext(), which is what the extension shows without AI.
  function localBaseline(rules, findings) {
    const contextScore = findings?.score ?? 0;
    const ruleReasons = rules.reasons.filter(r => !(contextScore > 0 && r === NO_SIGNS_REASON));
    return {
      ruleScore: rules.score,
      contextScore,
      score: Math.min(100, rules.score + contextScore),
      reasons: [...ruleReasons, ...(findings?.reasons || [])]
    };
  }

  // Credible impersonation from context.js: the sender claims a known brand but mails from a
  // domain that brand doesn't use. It's the only high-severity "sender" finding context.js emits
  // (free-mail and unknown-sender findings are lower), and like a lookalike link it is checked
  // against a fixed brand list rather than inferred from wording.
  function hasStrongContextEvidence(context) {
    return Array.isArray(context?.findings)
      && context.findings.some(f => f?.type === "sender" && f?.severity === "high");
  }

  const aiFailure = code => Object.assign(new Error(code), { code });

  // Rule-based result optionally combined with a backend AI verdict. Never throws:
  // any AI failure falls back to the local result with ai.status "skipped" or "error".
  //
  // Default mode (unchanged contract): AI eligibility and blending use the rule score R only;
  // context is sent to the backend but never scored.
  //
  // includeContextScore: true (one pipeline for rules + context + AI):
  //   - eligibility and blending use L = min(100, R + C), so context counts exactly once;
  //   - the result carries ruleScore, contextScore, localScore, context reasons, the context
  //     object itself (as applyContext() does) and ai.reason, so a caller must not apply
  //     context again afterwards;
  //   - strong evidence (a suspicious link, or credible sender impersonation) keeps the score at
  //     or above L: AI may raise it but not talk it down. Otherwise AI may lower it by at most
  //     policy.maxAiReduction.
  async function analyzeEmailWithAI(email, options = {}) {
    const {
      context = null,
      endpoint = null,
      fetchImpl = typeof root.fetch === "function" ? (...args) => root.fetch(...args) : null,
      timeoutMs = 8000,
      includeContextScore = false
    } = options;
    const policy = resolvePolicy(options.policy);
    const { strongEvidence: strongRuleEvidence, ...rules } = evaluateRules(email);
    const findings = normalizeContext(context);
    const local = includeContextScore ? localBaseline(rules, findings) : null;
    const baseScore = local ? local.score : rules.score;
    const strongEvidence = strongRuleEvidence || (local !== null && hasStrongContextEvidence(context));

    const finish = (score, ai) => {
      if (!local) {
        // Legacy shape, kept exactly for existing callers and tests.
        const { reason, ...legacyAi } = ai;
        return ai.status === "ok"
          ? { score, verdict: verdictFor(score), reasons: [...rules.reasons, ...ai.reasons.map(r => `AI: ${r}`)],
              urlCount: rules.urlCount, ruleScore: rules.score, ai: legacyAi }
          : { ...rules, ruleScore: rules.score, ai: legacyAi };
      }
      const result = {
        score,
        verdict: verdictFor(score),
        reasons: [...local.reasons, ...ai.reasons.map(r => `AI: ${r}`)],
        urlCount: rules.urlCount,
        ruleScore: local.ruleScore,
        contextScore: local.contextScore,
        localScore: local.score,
        ai
      };
      if (context && typeof context === "object") result.context = context;
      return result;
    };
    const fallback = (status, reason) => finish(baseScore, { status, score: null, reasons: [], reason });

    if (!endpoint || typeof fetchImpl !== "function") return fallback("skipped", "disabled");
    if (!shouldCallAI(baseScore, policy)) return fallback("skipped", "policy");

    const payload = {
      email: {
        subject: String(email?.subject || ""),
        sender: String(email?.sender || ""),
        body: String(email?.body || ""),
        links: Array.isArray(email?.links) ? email.links.filter(l => typeof l === "string") : []
      },
      context: findings
    };

    const controller = typeof AbortController === "function" ? new AbortController() : null;
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller?.abort();
        reject(aiFailure("timeout"));
      }, timeoutMs);
    });

    try {
      const request = (async () => {
        let response;
        try {
          response = await fetchImpl(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            signal: controller?.signal
          });
        } catch (_) {
          throw aiFailure("network_error");
        }
        if (!response?.ok) throw aiFailure("http_error");
        try {
          return parseAiResponse(await response.json());
        } catch (_) {
          throw aiFailure("invalid_response");
        }
      })();
      request.catch(() => {}); // a late failure after a timeout is already handled
      const ai = await Promise.race([request, timeout]);
      const score = combineScores(baseScore, ai.score, strongEvidence, policy);
      return finish(score, { status: "ok", score: ai.score, reasons: ai.reasons, reason: null });
    } catch (err) {
      return fallback("error", err?.code || "network_error");
    } finally {
      clearTimeout(timer);
    }
  }

  const api = { analyzeEmail, analyzeEmailWithAI, extractUrls, shouldCallAI, combineScores, DEFAULT_AI_POLICY };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PhishGuardDetector = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
