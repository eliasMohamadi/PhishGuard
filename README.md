# PhishGuard

**AI-assisted phishing detection for Gmail.**

PhishGuard is a Chrome extension that helps users identify potentially malicious emails through local rule-based detection, inbox-context analysis, and an optional AI-assisted review.

Built at Hacklanta (**with the help of 8 Red Bulls**), PhishGuard combines explainable risk scoring with an opt-in Google Gemini integration to help users understand *why* an email may be suspicious.

# Toolbar Preview
<img width="1794" height="897" alt="toolbarOverlay" src="https://github.com/user-attachments/assets/4668986e-4dac-4815-8fbe-1b95594f4f5a" />

# In Email UI
<img width="1862" height="961" alt="emailUI" src="https://github.com/user-attachments/assets/bf7a9eb0-52d7-4ef7-88c5-262361a9aaea" />

# Email Overlay
<img width="1859" height="969" alt="emailOverlay" src="https://github.com/user-attachments/assets/f42124dc-9e06-4279-a63a-90610c48cbe2" />



## Features

- **Local phishing detection:** Analyzes suspicious language, links, sender indicators, and requests for sensitive information.
- **Inbox-context analysis:** Looks for inconsistencies involving sender identity, unverified claims, and unusual requests.
- **Explainable risk scoring:** Groups detected signals by category and provides a recommended action.
- **Optional AI review:** Uses Google Gemini when enabled and the local score falls within an uncertain range.
- **Privacy-conscious design:** Keeps local checks in the browser, requires explicit opt-in for AI analysis, and limits the information sent to the backend.

## How It Works

1. **Analyze locally:** Rule-based detection and inbox-context checks calculate an initial risk score.
2. **Evaluate uncertainty:** Clear high-risk results are flagged immediately, while AI review is considered only for eligible scores when the user has enabled it.
3. **Present the findings:** The extension displays a risk badge, explains the detected signals, and recommends an action.
4. **Fall back gracefully:** If AI review is disabled, unnecessary, or unavailable, the local result remains available.

## Tech Stack

- **Extension:** JavaScript, HTML, CSS, Chrome Extensions API (Manifest V3)
- **Backend:** Node.js, Express
- **AI:** Google Gemini API
- **Testing:** Node.js built-in test runner and browser-based overlay tests

## Getting Started

### Requirements

Google Chrome and Git. Node.js 22 or newer is required for the backend and tests.

### Install the extension

1. Clone this repository.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer mode**.
4. Select **Load unpacked** and choose the repository root containing `manifest.json`.

The extension can perform local analysis without the backend.

### Enable AI review

1. Navigate to the `server` directory.
2. Install dependencies and create your environment file:

   ```bash
   cd server
   npm install
   cp .env.example .env
   ```

   In PowerShell, use `Copy-Item .env.example .env` instead.

3. Configure `GEMINI_API_KEY` and `GEMINI_MODEL` in `server/.env`.
4. Start the backend:

   ```bash
   npm start
   ```

5. Open the extension popup, enable AI review, and grant the requested local backend permission.

Never commit your API key or the `server/.env` file.

## Testing

Run the extension tests from the repository root:

```bash
node --test "tests/*.test.js"
```

Run the backend tests from the `server` directory:

```bash
npm test
```

See the testing documentation for browser-test requirements and the verified results from the latest test run.

## Limitations

PhishGuard is a hackathon prototype, not a guarantee that an email is safe. Its heuristic scores have not been validated against a labeled real-world dataset. Detection is limited by its rules, available inbox context, and Gmail's page structure. The backend is designed for local use, not as a publicly hosted production service.

## Technical Documentation

See [`docs/TECHNICAL_DESIGN.md`](docs/TECHNICAL_DESIGN.md) for the detailed scoring algorithm, architecture, API contract, privacy and security controls, testing strategy, and project structure.

## Project

Developed collaboratively at Hacklanta.

[View source code](https://github.com/eliasMohamadi/PhishGuard)
