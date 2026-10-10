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
    const verdict = score >= 60 ? "High risk" : score >= 30 ? "Use caution" : "Lower risk";
    return { score, verdict, reasons, urlCount: urls.length };
  }

  if (typeof module !== "undefined" && module.exports) module.exports = { analyzeEmail, extractUrls };
  root.PhishGuardDetector = { analyzeEmail, extractUrls };
})(typeof globalThis !== "undefined" ? globalThis : this);
