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
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      response = await requestEmail(tab.id);
    }

    if (!response?.ok) throw new Error(response?.error || "Could not read the open email.");
    const result = PhishGuardDetector.analyzeEmail(response.email);
    renderResult(result);
    statusEl.textContent = "Scanned locally. Email content was not sent to an AI service.";
  } catch (error) {
    statusEl.textContent = error.message || "Could not analyze this email.";
  } finally {
    analyzeBtn.disabled = false;
  }
});
