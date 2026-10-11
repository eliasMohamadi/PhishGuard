# PhishGuard website

Static landing page for PhishGuard: plain HTML, CSS and JavaScript, with no build step, no dependencies and no external requests. It's separate from the Chrome extension and the backend.

## Preview locally

```
node website/serve.js        # http://127.0.0.1:4173
```

You can also open `website/index.html` directly in a browser.

## Configure links

All link settings live in `config.js`:

| Setting | Effect |
|---|---|
| `chromeWebStoreUrl` | `null` (current): install buttons lead to the "Get PhishGuard" section, which marks the store listing as coming soon and shows the developer-preview (load unpacked) steps. Set it to the real listing URL and every install button becomes **Add to Chrome**, linking to the store. |
| `githubUrl` | Source repository for the developer preview and the footer. |
| `contactUrl` | `null` hides the footer's Contact link. Set an `https://` or `mailto:` URL to show it. |

## Before publishing the site

- In `index.html`, change `og:image` and `twitter:image` to absolute URLs on the final domain, and add `<meta property="og:url">`.
- `assets/og-image.png` (1200×630) is a screenshot of the hero; regenerate it if the hero changes.
- Keep the page copy in line with the extension: if detection, AI review or data handling changes, update the Features, Security and FAQ sections.
- The hero mockup is a static illustration with a fictional sender; it isn't connected to Gmail.

Any static host works (for example GitHub Pages pointed at this folder). `serve.js` is only for local preview.
