// Context checks: compare the open email against other recent mail in the inbox.
// Runs locally; recent-email data never leaves the browser.
(function (root) {
  "use strict";

  const FREE_MAIL = [
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "zoho.com"
  ];
  // Brand name -> domains the brand legitimately sends mail from.
  const BRANDS = {
    usps: ["usps.com"], fedex: ["fedex.com"], ups: ["ups.com"], dhl: ["dhl.com"],
    amazon: ["amazon.com"], irs: ["irs.gov"], paypal: ["paypal.com"], netflix: ["netflix.com"],
    microsoft: ["microsoft.com", "office.com"], apple: ["apple.com"],
    google: ["google.com"], chase: ["chase.com"], "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"]
  };

  // Claims an email can make, and what recent mail would back each one up.
  // anySender: supporting mail may come from anyone (e.g. a store's order confirmation
  // backs up a carrier's delivery notice); otherwise it must come from the same sender or brand.
  const CLAIMS = [
    {
      label: "a package delivery",
      evidence: "an order confirmation or shipping notice",
      detect: /\b(?:usps|fedex|ups|dhl|package|parcel|shipment|redeliver\w*|delivery (?:attempt|failed|notice)|tracking number)\b/i,
      support: /\b(?:your order|order (?:confirm\w*|#|number|placed|received)|has shipped|shipped|out for delivery|tracking (?:number|#)|purchase|receipt)\b/i,
      anySender: true,
      weight: 15
    },
    {
      label: "a refund, prize, or payout",
      evidence: "a recent purchase or return",
      detect: /\b(?:refund|you(?:'ve| have) won|winner|prize|claim your (?:reward|gift)|cash ?back)\b/i,
      support: /\b(?:return|refund|your order|purchase|receipt)\b/i,
      anySender: true,
      weight: 12
    },
    {
      label: "an invoice or payment due",
      evidence: "earlier billing mail from this sender",
      detect: /\b(?:invoice|payment (?:due|overdue|failed|declined)|outstanding balance|billing (?:issue|problem)|past due)\b/i,
      anySender: false,
      weight: 12
    },
    {
      label: "an account security alert",
      evidence: "earlier mail from this service",
      detect: /\b(?:sign[- ]?in attempt|unusual (?:sign[- ]?in|activity)|password (?:reset|change|expir\w*)|account (?:locked|suspended|disabled|verification))\b/i,
      anySender: false,
      weight: 10
    }
  ];

  // Requests that are unusual coming from someone you have no history with.
  // bec: risky even from a known sender, whose account may have been taken over.
  const REQUESTS = [
    { rx: /\bgift ?cards?\b/i, label: "buy gift cards", bec: true },
    { rx: /\b(?:wire|bank) transfer\b|\bsend (?:the )?(?:money|funds|payment)\b/i, label: "send money", bec: true },
    { rx: /\b(?:new|updated?|change[ds]?) (?:bank|banking|payment|account|direct deposit) (?:details|information|info)\b/i, label: "change payment details", bec: true },
    { rx: /\b(?:keep this|this is) (?:confidential|between us)\b|\bdon'?t (?:tell|share this with) anyone\b/i, label: "keep the request secret", bec: true },
    { rx: /\b(?:redelivery|customs|shipping|delivery|processing) fee\b|\bsmall (?:fee|payment)\b/i, label: "pay a small fee" },
    { rx: /\b(?:confirm|verify|update|enter|provide) (?:your )?(?:password|login|credentials|card|billing|payment)\b/i, label: "enter login or card details" },
    { rx: /\b(?:open|download|enable) (?:the )?(?:attached|attachment|file|macros?|editing|content)\b/i, label: "open an attachment or file" },
    { rx: /\bcall (?:us|this number|our (?:support|team))\b/i, label: "call a phone number" }
  ];

  function extractAddress(text) {
    const match = String(text || "").match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/i);
    return match ? match[0].toLowerCase() : "";
  }

  function domainOf(address) {
    return address.split("@")[1] || "";
  }

  // Rough registrable domain; keeps three labels for forms like example.co.uk.
  function baseDomain(host) {
    const labels = host.split(".");
    const keep = labels.length > 2 && labels[labels.length - 1].length === 2
      && labels[labels.length - 2].length <= 3 ? 3 : 2;
    return labels.slice(-keep).join(".");
  }

  function isOnDomain(host, domain) {
    return host === domain || host.endsWith(`.${domain}`);
  }

  function normalizeSubject(subject) {
    return String(subject || "").replace(/^\s*((re|fwd?|fw)\s*:\s*)+/i, "").trim().toLowerCase();
  }

  function wordRx(phrase) {
    return new RegExp(`\\b${phrase.replace(/\s+/g, "\\s+")}\\b`, "i");
  }

  // Accepts { sender } or { senders: [] } entries, as produced by readRecentEmails().
  function normalizeRecent(list) {
    if (!Array.isArray(list)) return [];
    const seen = new Set();
    return list.map(item => {
      const senders = (Array.isArray(item?.senders) ? item.senders : [item?.sender])
        .map(extractAddress).filter(Boolean);
      return {
        senders,
        domains: senders.map(domainOf),
        subject: String(item?.subject || ""),
        text: `${item?.subject || ""}\n${item?.snippet || item?.body || ""}`
      };
    }).filter(item => {
      // Gmail keeps hidden copies of list views, so the same row can appear more than once.
      const key = `${item.senders.join(",")}|${normalizeSubject(item.subject)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // Best-effort scrape of the Gmail message list (works while it is in the DOM, even if hidden).
  function readRecentEmails(doc = root.document, limit = 50) {
    if (!doc?.querySelectorAll) return [];
    return [...doc.querySelectorAll("tr.zA")].slice(0, limit).map(row => ({
      senders: [...row.querySelectorAll(".yW [email]")].map(el => el.getAttribute("email")),
      subject: row.querySelector(".bog")?.textContent || "",
      snippet: row.querySelector(".y2")?.textContent || ""
    }));
  }

  function analyzeContext(input, recentEmails) {
    const subject = String(input?.subject || "");
    const body = String(input?.body || "");
    const text = `${subject}\n${body}`;
    const address = extractAddress(input?.sender);
    const domain = domainOf(address);
    const senderBase = domain ? baseDomain(domain) : "";
    const freeMail = FREE_MAIL.includes(senderBase);
    const senderName = String(input?.senderName || String(input?.sender || "").replace(/<[^>]*>/, ""));

    // Leave the open email itself out so it can't vouch for its own claims.
    const currentSubject = normalizeSubject(subject);
    const recent = normalizeRecent(recentEmails).filter(r => !(currentSubject
      && normalizeSubject(r.subject) === currentSubject
      && (!address || r.senders.includes(address))));

    const findings = [];
    const add = (type, weight, reason) => findings.push({
      type, weight, reason, severity: weight >= 15 ? "high" : weight >= 8 ? "medium" : "low"
    });

    // Sender identity: claimed brand vs. the domain actually sending. A brand counts as claimed
    // when it's in the display name, leads the subject ("USPS: ..."), or is a sender domain label.
    const domainLabels = domain.split(/[.-]/);
    const claimedBrands = Object.keys(BRANDS).filter(brand =>
      wordRx(brand).test(senderName)
      || new RegExp(`^\\W*${wordRx(brand).source}`, "i").test(subject)
      || domainLabels.includes(brand.replace(/\s+/g, "")));
    const impersonated = claimedBrands.filter(brand =>
      domain && !BRANDS[brand].some(d => isOnDomain(domain, d)));
    if (impersonated.length) {
      add("sender", 20, `Claims to be ${impersonated.map(b => b.toUpperCase()).join("/")} but was sent from ${domain}.`);
    }

    const fromSender = r => r.senders.includes(address)
      || (!freeMail && senderBase && r.domains.some(d => isOnDomain(d, senderBase)));
    const knownSender = !!address && recent.some(fromSender);

    const claims = CLAIMS.filter(claim => claim.detect.test(text));
    if (freeMail && !knownSender && !impersonated.length && (claimedBrands.length || claims.length)) {
      add("sender", 12, `A business-style message was sent from a personal ${senderBase} account.`);
    }

    if (!recent.length) {
      add("info", 0, "Recent inbox emails weren't available, so the sender's claims couldn't be cross-checked.");
      return finish(false);
    }

    if (address && !knownSender) {
      add("sender", 8, "This sender doesn't appear in your other recent emails.");
    }

    // Does recent mail back up what this email claims?
    const brandDomains = claimedBrands.flatMap(brand => BRANDS[brand]);
    for (const claim of claims) {
      const supported = recent.some(r =>
        (fromSender(r) && !impersonated.length)
        || r.domains.some(d => brandDomains.some(b => isOnDomain(d, b)))
        || (claim.anySender && claim.support.test(r.text)));
      if (supported) {
        add("support", 0, `Recent emails appear consistent with ${claim.label}.`);
      } else {
        add("claim", claim.weight, `Mentions ${claim.label}, but no related recent email (such as ${claim.evidence}) was found.`);
      }
    }

    // Unexpected requests, weighed by whether you have any history with the sender.
    const requests = REQUESTS.filter(req => req.rx.test(text));
    if (requests.length && !knownSender) {
      add("request", Math.min(25, 10 * requests.length),
        `An unfamiliar sender asks you to ${requests.map(r => r.label).join(", ")}.`);
    } else if (requests.some(req => req.bec)) {
      add("request", 8, `A known sender asks you to ${requests.filter(r => r.bec).map(r => r.label).join(", ")}; `
        + "their account could be compromised, so confirm through another channel.");
    }

    return finish(true);

    function finish(available) {
      return {
        available,
        knownSender: available ? knownSender : null,
        recentCount: recent.length,
        score: Math.min(40, findings.reduce((sum, f) => sum + f.weight, 0)),
        reasons: findings.map(f => f.reason),
        findings
      };
    }
  }

  // Merges context findings into a PhishGuardDetector.analyzeEmail() result.
  function applyContext(result, context) {
    if (!context) return result;
    const score = Math.min(100, (result?.score || 0) + context.score);
    const baseReasons = (result?.reasons || []).filter(reason =>
      !(context.score > 0 && /^No obvious warning signs/.test(reason)));
    return {
      ...result,
      score,
      verdict: score >= 60 ? "High risk" : score >= 30 ? "Use caution" : "Lower risk",
      reasons: [...baseReasons, ...context.reasons],
      context
    };
  }

  const api = { analyzeContext, readRecentEmails, applyContext };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PhishGuardContext = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
