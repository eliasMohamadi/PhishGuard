# PhishGuard

A Chrome Extension Manifest V3 hackathon MVP that checks an open Gmail message for common phishing signals.

## Features
- Heuristic risk score (0–100)
- Urgency and sensitive-information language signals
- Basic suspicious URL and domain checks
- Reasons shown in a small popup
- Local-only analysis; no email content is sent to an AI service

## Load in Chrome
1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select this folder (the folder containing `manifest.json`).
5. Open or refresh Gmail, open an email, then click the PhishGuard toolbar icon and **Analyze open email**.

## Notes
This is a heuristic prototype, not a guarantee of safety. Gmail's HTML structure changes, so message extraction selectors may need adjustment. Never paste API secrets into extension JavaScript. If an AI service is added, put the secret behind a server-side endpoint and avoid sending email content without clear user consent.
