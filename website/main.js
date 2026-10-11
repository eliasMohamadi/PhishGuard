// Small progressive enhancements. The page is fully readable without JavaScript.
(function () {
  "use strict";

  const config = window.PHISHGUARD_SITE || {};
  const isUrl = value => typeof value === "string" && /^(https:\/\/|mailto:)/.test(value);
  document.documentElement.classList.add("js");

  // Install buttons: link straight to the store once a listing is configured; otherwise they
  // stay as links to the "Get PhishGuard" section, which explains the developer preview.
  if (isUrl(config.chromeWebStoreUrl)) {
    document.querySelectorAll("[data-install]").forEach(link => {
      link.href = config.chromeWebStoreUrl;
      link.target = "_blank";
      link.rel = "noopener";
      link.firstChild.textContent = "Add to Chrome ";
    });
    const status = document.querySelector("[data-store-status]");
    const text = document.querySelector("[data-store-text]");
    const storeLink = document.querySelector("[data-store-link]");
    if (status) { status.textContent = "Available"; status.classList.add("tag-accent"); }
    if (text) text.textContent = "Install PhishGuard from the Chrome Web Store in one click.";
    if (storeLink) {
      storeLink.href = config.chromeWebStoreUrl;
      storeLink.target = "_blank";
      storeLink.rel = "noopener";
      storeLink.hidden = false;
    }
  }

  if (isUrl(config.githubUrl)) {
    document.querySelectorAll("[data-github]").forEach(link => { link.href = config.githubUrl; });
  }

  const contact = document.querySelector("[data-contact]");
  if (contact && isUrl(config.contactUrl)) {
    contact.href = config.contactUrl;
    contact.hidden = false;
  }

  const year = document.querySelector("[data-year]");
  if (year) year.textContent = String(new Date().getFullYear());

  // Mobile navigation.
  const toggle = document.querySelector(".nav-toggle");
  const menu = document.getElementById("nav-menu");
  if (toggle && menu) {
    const setOpen = open => {
      menu.classList.toggle("open", open);
      toggle.setAttribute("aria-expanded", String(open));
      toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
      toggle.querySelector("use")?.setAttribute("href", open ? "#i-x" : "#i-menu");
    };
    toggle.addEventListener("click", () => setOpen(!menu.classList.contains("open")));
    menu.addEventListener("click", event => { if (event.target.closest("a")) setOpen(false); });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && menu.classList.contains("open")) { setOpen(false); toggle.focus(); }
    });
    matchMedia("(min-width: 761px)").addEventListener("change", event => { if (event.matches) setOpen(false); });
  }

  // Fade sections in once as they enter the viewport.
  const items = document.querySelectorAll(".reveal");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced || !("IntersectionObserver" in window)) {
    items.forEach(el => el.classList.add("in"));
  } else {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("in");
        observer.unobserve(entry.target);
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    items.forEach(el => observer.observe(el));
  }
})();
