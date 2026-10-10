# PhishGuard

A Chrome Extension Manifest V3 hackathon MVP that checks an open Gmail message for common phishing signals.

## Features
- Heuristic risk score (0–100)
- Urgency and sensitive-information language signals
- Basic suspicious URL and domain checks
- Reasons shown in a small popup
- Local analysis by default; no email content leaves the browser
- Optional AI review (off by default), via a local backend that calls Google Gemini

## Optional AI review
1. `cd server && npm install`, copy `.env.example` to `.env`, and set `GEMINI_API_KEY` and `GEMINI_MODEL` (use a billing-enabled key; see the note in `.env.example`).
2. `npm start` (listens on `http://127.0.0.1:3000`).
3. In the PhishGuard popup, turn on **AI review in Gmail** and allow access to `127.0.0.1:3000`.

When on, the open email's subject, sender, body (first 12,000 characters) and links, plus PhishGuard's short findings about it, go to that local server, which forwards them to Gemini. Other inbox emails are never sent. AI is only asked when the local score is uncertain (20–59). Turning it off stops further requests and removes the permission. The API key stays in `server/.env`; the extension never sees it.

## Load in Chrome
1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select this folder (the folder containing `manifest.json`).
5. Open or refresh Gmail, open an email, then click the PhishGuard toolbar icon and **Analyze open email**.

## Notes
This is a heuristic prototype, not a guarantee of safety. Gmail's HTML structure changes, so message extraction selectors may need adjustment. Never paste API secrets into extension JavaScript. If an AI service is added, put the secret behind a server-side endpoint and avoid sending email content without clear user consent.
