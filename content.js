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

  // Gmail's DOM changes frequently; these selectors are best-effort for a hackathon MVP.
  function findOpenMessage() {
    return lastVisible(".a3s.aiL")
      || lastVisible('[role="main"] .a3s')
      || lastVisible('[role="main"] [data-message-id]');
  }

  function readSubject() {
    return lastVisible("h2.hP")?.innerText
      || lastVisible('[role="main"] h2')?.innerText || "";
  }

  function readOpenEmail() {
    const subject = readSubject();
    const message = findOpenMessage();
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

  // Person 3's original auto-score card; used only if overlay.js isn't loaded.
  function showScore(result){
    let panel = document.getElementById("phishguard-auto-score");

    if(!panel){
      panel = document.createElement("div");
      panel.id = "phishguard-auto-score";

      Object.assign(panel.style, {
        position: "fixed",
        right: "20px",
        bottom: "20px",
        zIndex: "999999",
        background: "#ffffff",
        color: "#222222",
        padding: "16px",
        borderRadius: "12px",
        boxShadow: "0 4px 18px rgba(0,0,0,0.2)",
        fontFamily: "Arial, sans-serif",
        width: "240px"
      });

      document.body.appendChild(panel);
    }
    const color = result.score >=60
    ? "#dc2626"
        : result.score >= 30
            ? "#d97706"
            : "#16a34a";
    panel.replaceChildren();

    const title = document.createElement("strong");
    title.textContent = "PhishGuard Risk Score";
    panel.appendChild(title);

    const score = document.createElement("div");
    score.textContent = `${result.score}/100`;
    Object.assign(score.style, {
      fontSize: "28px",
      fontWeight: "bold",
      color,
      margin: "8px 0"
    });
    panel.appendChild(score);

    const verdict = document.createElement("div");
    verdict.textContent = result.verdict;
    panel.appendChild(verdict);

    result.reasons.forEach(reason => {
      const item = document.createElement("p");
      item.textContent = `• ${reason}`;
      item.style.fontSize = "12px";
      panel.appendChild(item);
    });
  }

  // AI review is off until the user opts in from the popup (stored as aiReviewEnabled).
  const AI_SETTING = "aiReviewEnabled";
  const settingsStore = window.chrome?.storage?.local;
  let aiEnabled = false;
  let settingsReady = !settingsStore;

  function sendToWorker(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, reply => {
        if (chrome.runtime.lastError) reject(new Error("Background worker unavailable"));
        else resolve(reply);
      });
    });
  }

  // Rules plus inbox-context checks, and AI review only when enabled; scoring is in detector.js.
  function analyzeOpenEmail(email) {
    return window.PhishGuardAnalysis.analyzeOpenEmail(email, {
      detector: window.PhishGuardDetector,
      context: window.PhishGuardContext,
      aiEnabled,
      sendMessage: sendToWorker
    });
  }

  // Cheap identity for the open message, so unchanged views don't re-run the analysis.
  function emailKey(message) {
    const container = message.closest(".adn, [data-message-id]");
    const id = container?.getAttribute("data-legacy-message-id")
      || container?.getAttribute("data-message-id") || "";
    const sender = container?.querySelector(".gD[email]")?.getAttribute("email") || "";
    return `${id}|${sender}|${readSubject()}|${message.innerText.length}`;
  }

  let lastEmailKey = "";
//automatically detects scams before user presses "analyze email" to give score
  function scanOpenEmail(){
    const overlay = window.PhishGuardOverlay;
    const message = findOpenMessage();

    if (!message) {
      lastEmailKey = "";
      overlay?.clear();
      return;
    }

    const key = emailKey(message);
    if (overlay && window.PhishGuardAnalysis) {
      if (!settingsReady) return; // the AI setting is loading; scan once it's known
      // The overlay ignores repeated keys (it only repositions) and discards stale results.
      // The AI setting is part of the key, so toggling it re-analyzes the open email.
      const useAI = aiEnabled;
      overlay.track(`${useAI ? "ai" : "local"}|${key}`, message,
        () => analyzeOpenEmail(readOpenEmail()), { aiEnabled: useAI });
      return;
    }

    if (key == lastEmailKey) return;
    lastEmailKey = key;

    if (!window.PhishGuardDetector) return;

    const result = window.PhishGuardDetector.analyzeEmail(readOpenEmail());
    showScore(result);
  }

  // Gmail mutates the DOM constantly; batch bursts into one scan.
  let scanTimer = 0;
  const observer = new MutationObserver(() => {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scanOpenEmail, 250);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  if (settingsStore) {
    settingsStore.get(AI_SETTING)
      .then(values => { aiEnabled = values?.[AI_SETTING] === true; })
      .catch(() => { aiEnabled = false; })
      .finally(() => { settingsReady = true; scanOpenEmail(); });
    // Turning AI off applies to the next analysis; an in-flight result is discarded because
    // the overlay key changes.
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local" || !changes[AI_SETTING]) return;
      aiEnabled = changes[AI_SETTING].newValue === true;
      scanOpenEmail();
    });
  }

  scanOpenEmail();

})();
