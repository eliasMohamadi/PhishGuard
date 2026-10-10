(() => {
  "use strict";

  // The popup may inject this file into a tab that already has it; register only once.
  if (window.__phishGuardLoaded) return;
  window.__phishGuardLoaded = true;

  function isVisible(el) {
    return !!el && el.getClientRects().length > 0;
  }

  // Gmail keeps hidden copies of previous views in the DOM, and a thread holds several
  // messages, so take the last visible match (the most recent expanded message).
  function lastVisible(selector) {
    const visible = [...document.querySelectorAll(selector)].filter(isVisible);
    return visible[visible.length - 1] || null;
  }

  // Gmail sometimes wraps outbound links as https://www.google.com/url?q=<real url>.
  function unwrapHref(href) {
    try {
      const url = new URL(href);
      if (/(^|\.)google\.com$/.test(url.hostname) && url.pathname === "/url") {
        return url.searchParams.get("q") || url.searchParams.get("url") || href;
      }
    } catch (_) { /* keep the original */ }
    return href;
  }

  function readOpenEmail() {
    // Gmail's DOM changes frequently; these selectors are best-effort for a hackathon MVP.
    const subject = lastVisible("h2.hP")?.innerText
      || lastVisible('[role="main"] h2')?.innerText || "";
    const message = lastVisible(".a3s.aiL")
      || lastVisible('[role="main"] .a3s')
      || lastVisible('[role="main"] [data-message-id]');
    const body = message?.innerText || "";

    // Prefer the sender header belonging to the same message as the body.
    const container = message?.closest(".adn, [data-message-id]");
    const senderElement = container?.querySelector(".gD[email]")
      || lastVisible(".gD[email]")
      || lastVisible('[role="main"] [email][name]');
    const sender = senderElement?.getAttribute("email")
      || senderElement?.getAttribute("name") || "";

    // innerText hides link destinations ("Click here"), so collect the real hrefs.
    const links = message
      ? [...message.querySelectorAll("a[href]")]
          .map(a => unwrapHref(a.href))
          .filter(href => /^https?:/i.test(href))
      : [];

    // Other inbox rows let the context checks see whether recent mail backs up this email.
    const recentEmails = window.PhishGuardContext?.readRecentEmails(document) || [];

    return { subject, sender, body, links, recentEmails };
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "PHISHGUARD_READ_EMAIL") {
      const email = readOpenEmail();
      if (!email.body && !email.sender) {
        sendResponse({
          ok: false,
          error: "No open email found. Open a message in Gmail and try again."
        });
      } else {
        sendResponse({ ok: true, email });
      }
    }
  });
})();
