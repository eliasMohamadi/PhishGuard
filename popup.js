const analyzeBtn = document.getElementById("analyzeBtn");
const scoreEl = document.getElementById("score");
const verdictEl = document.getElementById("verdict");
const summaryEl = document.getElementById("summary");
const reasonsEl = document.getElementById("reasons");
const statusEl = document.getElementById("status");
const scoreRing = document.getElementById("scoreRing");

function renderResult(result) {
  scoreEl.textContent = result.score;
  verdictEl.textContent = result.verdict;
  summaryEl.textContent = result.score >= 60
    ? "Several warning signs detected. Do not click links or share information until verified."
    : result.score >= 30
      ? "Some warning signs detected. Verify the sender and links independently."
      : "Few obvious warning signs detected. This does not prove the email is safe.";
  scoreRing.className = "score-ring " + (result.score >= 60 ? "high" : result.score >= 30 ? "medium" : "low");
  reasonsEl.replaceChildren();
  result.reasons.forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonsEl.appendChild(li);
  });
}

function requestEmail(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_READ_EMAIL" }, reply => {
      if (chrome.runtime.lastError) reject(new Error("Refresh Gmail and try again."));
      else resolve(reply);
    });
  });
}

analyzeBtn.addEventListener("click", async () => {
  analyzeBtn.disabled = true;
  statusEl.textContent = "Analyzing the open Gmail message…";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url?.startsWith("https://mail.google.com/")) {
      throw new Error("Open Gmail in this tab, open an email, then try again.");
    }

    let response;
    try {
      response = await requestEmail(tab.id);
    } catch (_) {
      // Tabs opened before the extension was installed or reloaded have no content script yet.
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["detector.js", "context.js", "analysis.js", "overlay.js", "content.js"] });
      response = await requestEmail(tab.id);
    }

    if (!response?.ok) throw new Error(response?.error || "Could not read the open email.");
    const email = response.email;
    const result = PhishGuardContext.applyContext(
      PhishGuardDetector.analyzeEmail(email),
      PhishGuardContext.analyzeContext(email, email.recentEmails)
    );
    renderResult(result);
    statusEl.textContent = "Scanned locally. This scan did not send email content to an AI service.";
  } catch (error) {
    statusEl.textContent = error.message || "Could not analyze this email.";
  } finally {
    analyzeBtn.disabled = false;
  }
});

// --- AI review opt-in (off by default). Must match background.js. ---
const AI_SETTING = "aiReviewEnabled";
const AI_ORIGIN = "http://127.0.0.1:3000/*";
const aiToggle = document.getElementById("aiToggle");
const aiStateEl = document.getElementById("aiState");
const aiStatusEl = document.getElementById("aiStatus");

function showAiState(enabled, message = "") {
  aiToggle.checked = enabled;
  aiStateEl.textContent = enabled ? "On" : "Off";
  aiStatusEl.textContent = message;
}

chrome.storage.local.get(AI_SETTING)
  .then(values => showAiState(values[AI_SETTING] === true))
  .catch(() => showAiState(false));

aiToggle.addEventListener("change", async () => {
  aiToggle.disabled = true;
  try {
    if (aiToggle.checked) {
      // Asked only from this click; without the permission AI stays off.
      let granted = false;
      try {
        granted = await chrome.permissions.request({ origins: [AI_ORIGIN] });
      } catch (_) { /* treated as denied */ }
      if (!granted) {
        await chrome.storage.local.set({ [AI_SETTING]: false });
        showAiState(false, "Permission wasn't granted, so AI review stays off.");
        return;
      }
      await chrome.storage.local.set({ [AI_SETTING]: true });
      showAiState(true, "AI review is on for emails you open in Gmail. Start the PhishGuard server to use it.");
    } else {
      await chrome.storage.local.set({ [AI_SETTING]: false });
      try {
        await chrome.permissions.remove({ origins: [AI_ORIGIN] });
      } catch (_) { /* the setting alone already stops requests */ }
      showAiState(false, "AI review is off. Nothing more is sent.");
    }
  } catch (_) {
    await chrome.storage.local.set({ [AI_SETTING]: false }).catch(() => {});
    showAiState(false, "Couldn't change the setting, so AI review is off.");
  } finally {
    aiToggle.disabled = false;
  }
});
