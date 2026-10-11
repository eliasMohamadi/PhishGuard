// Site configuration: the only place install and contact links are set.
// Leave a value as null until its destination really exists; the page adapts automatically.
window.PHISHGUARD_SITE = Object.freeze({
  // Chrome Web Store listing. While null, install buttons lead to the "Get PhishGuard" section,
  // which says the store listing is coming soon and shows the developer-preview install.
  // When published, set it, e.g. "https://chromewebstore.google.com/detail/phishguard/<id>".
  chromeWebStoreUrl: null,

  // Public source repository (used for the developer-preview install and the footer).
  githubUrl: "https://github.com/eliasMohamadi/PhishGuard",

  // Contact destination, e.g. "mailto:team@example.com". The footer hides Contact while null.
  contactUrl: null
});
