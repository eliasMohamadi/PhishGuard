// In-Gmail risk overlay: a compact badge on the open email's subject row that expands into a
// details panel. Rendered in a shadow root so Gmail's CSS and ours never collide.
// Content scripts call track(key, anchor, analyze) on every scan and clear() when no email is open.
(function (root) {
  "use strict";

  if (root.PhishGuardOverlay) return; // the popup may re-inject this file

  const HIGH = 60;
  const MEDIUM = 30;
  const CHART_MS = 800;

  // Signal categories. "rules" are detector.js reasons; the rest are context.js finding types.
  const CATEGORIES = {
    rules: { label: "Message & links", color: "#0b57d0",
      why: "Wording and link patterns that phishing emails commonly use." },
    sender: { label: "Sender identity", color: "#7cacf8",
      why: "Who the email claims to be doesn't match where it came from, or you haven't heard from this sender recently." },
    claim: { label: "Unverified claims", color: "#00639b",
      why: "It refers to an order, bill or alert that your recent inbox doesn't back up." },
    request: { label: "Unusual requests", color: "#3d4f6b",
      why: "It asks for money, sign-in or card details, or secrecy, which are common phishing goals." },
    context: { label: "Inbox context", color: "#9aa9c0",
      why: "Compared with your other recent emails." },
    ai: { label: "AI review", color: "#5e8fd6",
      why: "Observations from the AI model; treat them as supporting evidence, not proof." }
  };

  const STYLES = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .wrap {
      --accent: #0b57d0; --text: #1f1f1f; --muted: #5f6368; --line: #e3e6ea; --soft: #f6f8fc;
      --high: #b3261e; --high-bg: #fce8e6; --med: #8a4b00; --med-bg: #fef7e0; --low: #146c2e; --low-bg: #e6f4ea;
      position: fixed; inset: 0 auto auto 0; width: 0; height: 0; z-index: 2147483000;
      font: 13px/1.5 "Google Sans", Roboto, system-ui, -apple-system, "Segoe UI", sans-serif;
      color: var(--text);
    }
    button { font: inherit; cursor: pointer; }
    button:focus-visible, [tabindex]:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

    .badge {
      position: fixed; display: inline-flex; align-items: center; gap: 6px;
      padding: 3px 10px; border-radius: 999px; border: 1px solid #dadce0; background: #fff; color: #444746;
      font-size: 12px; font-weight: 500; white-space: nowrap; box-shadow: 0 1px 2px rgba(60,64,67,.15);
      transition: box-shadow .15s ease;
    }
    .badge:hover { box-shadow: 0 2px 6px rgba(60,64,67,.25); }
    .badge .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; flex: none; }
    .badge.low .dot { background: #1e8e3e; }
    .badge.medium { border-color: #f4c27a; background: var(--med-bg); color: var(--med); }
    .badge.high {
      padding: 6px 14px; gap: 8px; border: 2px solid var(--high); background: var(--high); color: #fff;
      font-size: 13px; font-weight: 700; box-shadow: 0 2px 10px rgba(179,38,30,.35);
    }
    .badge.high .dot { display: none; }
    .badge.error { border-color: #c4c7c5; background: #f8f9fa; }
    .badge.loading { cursor: progress; }
    .badge.loading .dot { background: transparent; border: 2px solid #c4c7c5; border-top-color: var(--accent); animation: spin .8s linear infinite; }
    .badge[aria-expanded="true"] { visibility: hidden; }

    .panel {
      position: fixed; display: flex; flex-direction: column; overflow: hidden;
      background: #fff; border: 1px solid #dadce0; border-radius: 16px;
      box-shadow: 0 12px 32px rgba(60,64,67,.24), 0 2px 6px rgba(60,64,67,.12);
      transform-origin: top right; animation: open .2s cubic-bezier(.2,0,0,1);
    }
    .panel[hidden] { display: none; }
    .head { display: flex; align-items: center; gap: 10px; padding: 12px 12px 12px 20px; border-bottom: 1px solid var(--line); }
    .logo { width: 22px; height: 22px; border-radius: 6px; background: var(--accent); color: #fff; display: grid; place-items: center; font-weight: 700; font-size: 12px; flex: none; }
    .head h2 { margin: 0; flex: 1; font-size: 14px; font-weight: 500; color: var(--text); }
    .close { width: 32px; height: 32px; border-radius: 50%; border: 0; background: transparent; color: #444746; font-size: 20px; line-height: 1; }
    .close:hover { background: #f1f3f4; }
    .body { padding: 4px 20px 20px; overflow: auto; flex: 1; }
    .foot { padding: 10px 20px; border-top: 1px solid var(--line); color: var(--muted); font-size: 11.5px; }

    section { padding-top: 16px; }
    section + section { margin-top: 16px; border-top: 1px solid var(--line); }
    h3 { margin: 0 0 10px; font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }

    .overall { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
    .score { font-size: 44px; font-weight: 600; line-height: 1; letter-spacing: -.02em; }
    .score small { font-size: 18px; font-weight: 500; color: var(--muted); margin-left: 1px; }
    .high .score { color: var(--high); }
    .headline { flex: 1; min-width: 180px; }
    .headline strong { display: block; font-size: 15px; font-weight: 600; margin-top: 6px; }
    .headline p { margin: 2px 0 0; color: var(--muted); }
    .pill { display: inline-flex; align-items: center; gap: 5px; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; background: var(--low-bg); color: var(--low); }
    .medium .pill { background: var(--med-bg); color: var(--med); }
    .high .pill { background: var(--high-bg); color: var(--high); }
    .meter { position: relative; height: 6px; margin: 14px 0 4px; border-radius: 3px; background: #e8eaed; }
    .meter span { position: absolute; inset: 0 auto 0 0; border-radius: 3px; background: var(--low); }
    .medium .meter span { background: #e37400; }
    .high .meter span { background: var(--high); }
    .meter i { position: absolute; top: -3px; width: 1px; height: 12px; background: #9aa0a6; }
    .scale { display: flex; justify-content: space-between; color: var(--muted); font-size: 11px; }

    .breakdown { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
    .donut { width: 112px; height: 112px; flex: none; }
    .donut text { font: 600 22px "Google Sans", Roboto, system-ui, sans-serif; fill: var(--text); }
    .donut .unit { font-size: 10px; font-weight: 500; fill: var(--muted); }
    .legend { list-style: none; margin: 0; padding: 0; flex: 1; min-width: 160px; }
    .legend li { display: flex; align-items: center; gap: 8px; padding: 3px 0; }
    .legend b { margin-left: auto; font-weight: 600; font-variant-numeric: tabular-nums; }
    .swatch { width: 10px; height: 10px; border-radius: 3px; flex: none; }
    .caption { margin: 8px 0 0; color: var(--muted); font-size: 11.5px; }

    .group + .group { margin-top: 12px; }
    .group h4 { margin: 0; font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .group .why { margin: 1px 0 6px 18px; color: var(--muted); font-size: 12px; }
    .group ul, .notes { margin: 0; padding: 0 0 0 18px; }
    .group li { margin: 3px 0; padding-left: 2px; }
    .group li::marker { color: var(--accent); }
    .notes { list-style: none; padding: 0; margin-top: 12px; color: var(--muted); font-size: 12px; }
    .notes li { padding: 6px 10px; border-radius: 8px; background: var(--soft); margin-top: 6px; }

    .action { padding: 12px 14px; border-radius: 10px; background: #eef3fd; border-left: 3px solid var(--accent); }
    .high .action { background: var(--high-bg); border-left-color: var(--high); }
    .action strong { display: block; font-weight: 600; }
    .action p { margin: 4px 0 0; }
    .retry { margin-top: 12px; padding: 6px 16px; border-radius: 999px; border: 1px solid var(--accent); background: #fff; color: var(--accent); font-weight: 500; }
    .retry:hover { background: #eef3fd; }

    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes open { from { opacity: 0; transform: scale(.96); } to { opacity: 1; transform: none; } }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation: none !important; transition: none !important; }
    }
  `;

  const SVG_NS = "http://www.w3.org/2000/svg";

  function levelOf(score) {
    return score >= HIGH ? "high" : score >= MEDIUM ? "medium" : "low";
  }

  function reducedMotion() {
    return root.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  }

  const isText = v => typeof v === "string" && v.trim();

  // Analysis output may come from the network later; accept only the agreed shape.
  function validResult(result) {
    if (!result || !Number.isFinite(result.score) || !Array.isArray(result.reasons)) return null;
    const findings = Array.isArray(result.context?.findings) ? result.context.findings : [];
    return {
      score: Math.max(0, Math.min(100, Math.round(result.score))),
      verdict: isText(result.verdict) ? result.verdict : "",
      reasons: result.reasons.filter(isText),
      findings: findings.filter(f => isText(f?.reason) && isText(f?.type) && Number.isFinite(f?.weight)),
      ai: result.ai || null
    };
  }

  // Group the real reasons by where they came from. Counts here are genuine signal counts,
  // which is what the chart shows; per-category risk points aren't exposed by the detector.
  function categorize(result) {
    const contextReasons = new Set(result.findings.map(f => f.reason));
    const groups = new Map();
    const notes = [];
    const add = (key, reason) => (groups.get(key) || groups.set(key, []).get(key)).push(reason);

    for (const reason of result.reasons) {
      if (contextReasons.has(reason) || /^No obvious warning signs/i.test(reason)) continue;
      if (/^AI:\s*/.test(reason)) add("ai", reason.replace(/^AI:\s*/, ""));
      else add("rules", reason);
    }
    for (const f of result.findings) {
      if (f.weight > 0) add(CATEGORIES[f.type] && f.type !== "ai" ? f.type : "context", f.reason);
      else notes.push(f.reason); // "info" (context unavailable) and "support" (inbox agrees)
    }
    const ordered = Object.keys(CATEGORIES).filter(k => groups.has(k)).map(k => ({ key: k, ...CATEGORIES[k], reasons: groups.get(k) }));
    return { groups: ordered, notes, total: ordered.reduce((n, g) => n + g.reasons.length, 0) };
  }

  const HEADLINES = {
    high: ["Strong warning signs of phishing", "Several signals match known phishing patterns."],
    medium: ["Some warning signs", "A few signals deserve a check before you act."],
    low: ["Few warning signs found", "A low score doesn't guarantee this email is safe."]
  };

  function recommendation(level, groups) {
    const asksForMoney = groups.some(g => g.key === "request");
    if (level === "high") {
      return ["Don't click links, open attachments or reply.",
        "If it might be genuine, contact the organization through its official website or a phone number you already trust. "
        + "You can report it with Gmail's “Report phishing” option."];
    }
    if (level === "medium") {
      return ["Verify before you act.", asksForMoney
        ? "Confirm any request for money, payment changes or sign-in details by contacting the sender through a channel you already trust."
        : "Check the sender's address and hover over links to see where they really go before clicking."];
    }
    return ["No specific action needed.", "Stay alert to unexpected requests for money, passwords or personal details."];
  }

  function el(tag, props = {}, children = []) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
  }

  function svg(tag, attrs = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }

  function visible(node) {
    return !!node && node.getClientRects().length > 0;
  }

  // The reading area is Gmail's main region; fall back to the viewport.
  function areaRect(anchor) {
    const r = anchor?.closest?.('[role="main"]')?.getBoundingClientRect();
    return r && r.width > 0 && r.height > 0
      ? r
      : { top: 0, left: 0, right: innerWidth, bottom: innerHeight, width: innerWidth, height: innerHeight };
  }

  // Preferred badge spot: the subject row, right-aligned but left of any Gmail controls in that
  // row (print, open in new window). Returns null if it would collide with the subject text.
  function subjectSpot(anchor, rightLimit, badgeW, badgeH, gap) {
    const scope = anchor.closest('[role="main"]') || document;
    const subject = [...scope.querySelectorAll("h2.hP")].find(visible);
    if (!subject) return null;
    const s = subject.getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(subject);
    const textRight = range.getBoundingClientRect().right;
    const row = subject.closest(".ha") || subject.parentElement;
    let right = rightLimit;
    for (const control of row.querySelectorAll('[role="button"], button, [data-tooltip]')) {
      if (subject.contains(control)) continue;
      const r = control.getBoundingClientRect();
      if (r.width && r.left >= textRight && r.bottom > s.top && r.top < s.bottom) right = Math.min(right, r.left - gap);
    }
    if (right - badgeW < textRight + gap) return null;
    return { top: s.top + (s.height - badgeH) / 2, right };
  }

  let host = null;
  let parts = null;
  let state = null; // { key, anchor, analyze, status: "loading"|"done"|"error", result, expanded, chartPlayed }
  let frame = 0;
  let chartFrame = 0;

  function mount() {
    if (host) return;
    host = el("div", { id: "phishguard-overlay-host" });
    const shadow = host.attachShadow({ mode: "open" });
    const wrap = el("div", { className: "wrap" });
    const badge = el("button", { className: "badge", type: "button" });
    badge.setAttribute("aria-controls", "pg-panel");
    badge.setAttribute("aria-expanded", "false");
    const panel = el("section", { className: "panel", id: "pg-panel", hidden: true });
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-labelledby", "pg-title");
    const live = el("div", { className: "sr" });
    live.setAttribute("aria-live", "polite");
    wrap.append(badge, panel, live);
    shadow.append(el("style", { textContent: STYLES }), wrap);
    document.body.appendChild(host);
    parts = { shadow, wrap, badge, panel, live };

    badge.addEventListener("click", () => setExpanded(true));
    panel.addEventListener("keydown", event => {
      if (event.key === "Escape") { event.stopPropagation(); setExpanded(false); }
    });
    addEventListener("resize", schedulePosition);
    addEventListener("scroll", schedulePosition, { capture: true, passive: true });
  }

  function unmount() {
    if (!host) return;
    removeEventListener("resize", schedulePosition);
    removeEventListener("scroll", schedulePosition, { capture: true });
    cancelAnimationFrame(frame);
    cancelAnimationFrame(chartFrame);
    host.remove();
    host = parts = null;
  }

  function schedulePosition() {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(position);
  }

  // Badge on the subject row (or level with the message top if that row is crowded); panel
  // right-aligned below it at about two-thirds of the reading area so part of the email stays visible.
  function position() {
    if (!parts || !state || !state.anchor.isConnected) return; // the next scan clears or re-tracks
    const { badge, panel } = parts;
    const area = areaRect(state.anchor);
    const gap = 12;
    const viewW = document.documentElement.clientWidth;
    const rightLimit = area.right - 2 * gap; // clear of the reading area's scrollbar
    const bw = badge.offsetWidth;
    const bh = badge.offsetHeight;
    const spot = subjectSpot(state.anchor, rightLimit, bw, bh, gap)
      || { top: state.anchor.getBoundingClientRect().top, right: rightLimit };
    const top = Math.min(Math.max(spot.top, area.top + gap), area.bottom - bh - gap);
    Object.assign(badge.style, { top: `${top}px`, right: `${viewW - spot.right}px` });

    const width = Math.min(640, area.width - 3 * gap, Math.max(area.width * 0.65, 300));
    const panelTop = Math.max(Math.min(top, area.bottom - 240), area.top + gap);
    Object.assign(panel.style, {
      top: `${panelTop}px`,
      right: `${viewW - rightLimit}px`,
      width: `${width}px`,
      maxHeight: `${Math.max(220, Math.min(area.bottom - panelTop - gap, area.height * 0.7))}px`
    });
  }

  function setExpanded(expanded) {
    if (!state || (expanded && state.status === "loading")) return;
    state.expanded = expanded;
    render();
    if (expanded) parts.panel.querySelector(".close")?.focus();
    else parts.badge.focus();
  }

  function badgeText() {
    const { status, result } = state;
    if (status === "loading") return ["PhishGuard: scanning…", "PhishGuard is analyzing this email"];
    if (status === "error") return ["PhishGuard: analysis unavailable", "PhishGuard could not analyze this email. Show details"];
    const { score } = result;
    const level = levelOf(score);
    if (level === "high") return [`⚠ High risk · ${score}%`, `Warning: high phishing risk, ${score} percent. Show details`];
    const word = level === "medium" ? "Caution" : "Low risk";
    return [`${word} ${score}%`, `PhishGuard: ${word.toLowerCase()}, ${score} percent phishing risk. Show details`];
  }

  function render() {
    const { badge, panel, shadow } = parts;
    const { status, result, expanded } = state;
    const level = result ? levelOf(result.score) : "";
    const [text, label] = badgeText();
    badge.className = `badge ${status === "done" ? level : status}`;
    badge.setAttribute("aria-expanded", String(expanded));
    badge.setAttribute("aria-label", label);
    badge.disabled = status === "loading";
    const dot = el("span", { className: "dot" });
    dot.setAttribute("aria-hidden", "true");
    badge.replaceChildren(dot, el("span", { textContent: text }));

    const hadFocus = panel.contains(shadow.activeElement);
    panel.hidden = !expanded;
    panel.className = `panel ${level}`;
    cancelAnimationFrame(chartFrame);
    if (expanded) {
      panel.replaceChildren(...panelContent());
      if (hadFocus) panel.querySelector(".close")?.focus(); // e.g. the Retry button was replaced
    }
    position();
  }

  function announce(message) {
    if (parts) parts.live.textContent = message;
  }

  function header() {
    const close = el("button", { className: "close", type: "button", textContent: "×", title: "Close (Esc)" });
    close.setAttribute("aria-label", "Close PhishGuard details");
    close.addEventListener("click", () => setExpanded(false));
    const logo = el("span", { className: "logo", textContent: "P" });
    logo.setAttribute("aria-hidden", "true");
    return el("header", { className: "head" }, [logo, el("h2", { id: "pg-title", textContent: "PhishGuard security check" }), close]);
  }

  function section(title, children) {
    return el("section", {}, [el("h3", { textContent: title }), ...children]);
  }

  function panelContent() {
    if (state.status === "loading") {
      return [header(), el("div", { className: "body" }, [section("Overall risk", [el("p", { textContent: "Analyzing this email…" })])])];
    }
    if (state.status === "error") {
      const retry = el("button", { className: "retry", type: "button", textContent: "Try again" });
      retry.addEventListener("click", () => run(state));
      return [header(), el("div", { className: "body" }, [section("Analysis unavailable", [
        el("p", { textContent: "PhishGuard couldn't finish analyzing this email, so there's no risk score. This is not a safety rating." }),
        el("div", { className: "action" }, [
          el("strong", { textContent: "Treat unexpected requests with care." }),
          el("p", { textContent: "Verify the sender through a channel you already trust before clicking links or sharing information." })
        ]),
        retry
      ])])];
    }

    const { score, ai } = state.result;
    const level = levelOf(score);
    const { groups, notes, total } = categorize(state.result);
    const [headline, sub] = HEADLINES[level];
    const icon = level === "high" ? "⚠" : level === "medium" ? "!" : "✓";
    const pill = el("span", { className: "pill" }, [el("span", { textContent: icon }), el("span", { textContent: state.result.verdict || headline })]);
    pill.firstChild.setAttribute("aria-hidden", "true");
    const scoreEl = el("div", { className: "score" }, [String(score), el("small", { textContent: "%" })]);
    scoreEl.setAttribute("aria-label", `Risk score ${score} percent`);

    const meter = el("div", { className: "meter" }, [
      el("span", { style: `width:${score}%` }), el("i", { style: `left:${MEDIUM}%` }), el("i", { style: `left:${HIGH}%` })
    ]);
    meter.setAttribute("aria-hidden", "true");
    const scale = el("div", { className: "scale" }, ["Low", "Caution", "High"].map(t => el("span", { textContent: t })));
    scale.setAttribute("aria-hidden", "true");

    const sections = [section("Overall risk", [
      el("div", { className: "overall" }, [scoreEl, el("div", { className: "headline" }, [pill, el("strong", { textContent: headline }), el("p", { textContent: sub })])]),
      meter, scale
    ])];

    if (groups.length >= 2) {
      sections.push(section("Signal breakdown", [breakdown(groups, total)]));
    } else if (groups.length === 1) {
      sections.push(section("Signal breakdown", [el("p", {
        textContent: `All ${total} signal${total === 1 ? "" : "s"} came from one category: ${groups[0].label.toLowerCase()}.`
      })]));
    }

    const signalNodes = groups.length
      ? groups.map(g => {
          const swatch = el("span", { className: "swatch", style: `background:${g.color}` });
          swatch.setAttribute("aria-hidden", "true");
          return el("div", { className: "group" }, [
            el("h4", {}, [swatch, `${g.label} (${g.reasons.length})`]),
            el("p", { className: "why", textContent: g.why }),
            el("ul", {}, g.reasons.map(r => el("li", { textContent: r })))
          ]);
        })
      : [el("p", { textContent: "No specific warning signals were found." })];
    if (notes.length) signalNodes.push(el("ul", { className: "notes" }, notes.map(n => el("li", { textContent: n }))));
    sections.push(section("Detected signals", signalNodes));

    const [act, detail] = recommendation(level, groups);
    sections.push(section("Recommended action", [el("div", { className: "action" }, [el("strong", { textContent: act }), el("p", { textContent: detail })])]));

    const source = ai?.status === "ok" ? "Rules, inbox context and AI review." : "Checked locally with rules and inbox context; no AI review.";
    return [header(), el("div", { className: "body" }, sections),
      el("footer", { className: "foot", textContent: `${source} A heuristic estimate, not a guarantee.` })];
  }

  // Donut of signal counts per category. Slice angles are exactly count / total.
  function breakdown(groups, total) {
    const r = 42;
    const c = 2 * Math.PI * r;
    const chart = svg("svg", { class: "donut", viewBox: "0 0 112 112", role: "img",
      "aria-label": `Warning signals by category: ${groups.map(g => `${g.label} ${g.reasons.length}`).join(", ")}. ${total} in total.` });
    chart.append(svg("circle", { cx: 56, cy: 56, r, fill: "none", stroke: "#eef1f5", "stroke-width": 14 }));
    const ring = svg("g", { transform: "rotate(-90 56 56)" });
    let start = 0;
    const slices = groups.map(g => {
      const frac = g.reasons.length / total;
      const node = svg("circle", { cx: 56, cy: 56, r, fill: "none", stroke: g.color, "stroke-width": 14 });
      ring.append(node);
      const slice = { node, start, frac };
      start += frac;
      return slice;
    });
    const count = svg("text", { x: 56, y: 58, "text-anchor": "middle" });
    count.textContent = String(total);
    const unit = svg("text", { x: 56, y: 74, "text-anchor": "middle", class: "unit" });
    unit.textContent = total === 1 ? "signal" : "signals";
    chart.append(ring, count, unit);

    // Progress p sweeps every slice clockwise from 12 o'clock; at p = 1 each arc is exactly frac * c.
    const draw = p => slices.forEach(s => {
      s.node.setAttribute("stroke-dasharray", `${s.frac * c * p} ${c}`);
      s.node.setAttribute("stroke-dashoffset", String(-s.start * c * p));
    });
    // Animate only on the first open for this email; reopening or re-rendering shows the final chart.
    if (state.chartPlayed || reducedMotion()) {
      draw(1);
    } else {
      state.chartPlayed = true;
      draw(0);
      let t0 = null;
      const ease = t => (t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
      const step = now => {
        t0 ??= now; // time from the first frame, on the rAF clock
        const t = Math.max(0, Math.min(1, (now - t0) / CHART_MS));
        draw(ease(t));
        if (t < 1) chartFrame = requestAnimationFrame(step);
      };
      chartFrame = requestAnimationFrame(step);
      // rAF pauses in background tabs; make sure the chart always ends at its true proportions.
      setTimeout(() => { cancelAnimationFrame(chartFrame); draw(1); }, CHART_MS + 100);
    }

    const legend = el("ul", { className: "legend" }, groups.map(g => {
      const swatch = el("span", { className: "swatch", style: `background:${g.color}` });
      swatch.setAttribute("aria-hidden", "true");
      return el("li", {}, [swatch, el("span", { textContent: g.label }), el("b", { textContent: String(g.reasons.length) })]);
    }));
    return el("div", {}, [
      el("div", { className: "breakdown" }, [chart, legend]),
      el("p", { className: "caption", textContent: "Number of warning signals in each category. Slice size reflects how many signals were found, not how much each adds to the score." })
    ]);
  }

  // Run (or re-run) the analysis for this tracked email. Results for an email the user has since
  // left are discarded, so a late analysis can't land on the wrong message.
  function run(current) {
    current.status = "loading";
    current.result = null;
    current.chartPlayed = false;
    render();
    announce("PhishGuard is analyzing this email.");
    Promise.resolve()
      .then(() => current.analyze())
      .then(validResult)
      .catch(() => null)
      .then(result => {
        if (state !== current) return;
        current.status = result ? "done" : "error";
        current.result = result;
        render();
        announce(result
          ? `PhishGuard: ${HEADLINES[levelOf(result.score)][0]}, risk score ${result.score} percent.`
          : "PhishGuard could not analyze this email.");
      });
  }

  // Show the overlay for the email identified by key. Same key: just reposition.
  function track(key, anchor, analyze) {
    if (!key || !anchor) return clear();
    if (state?.key === key) {
      state.anchor = anchor;
      return schedulePosition();
    }
    mount();
    state = { key, anchor, analyze, status: "loading", result: null, expanded: false, chartPlayed: false };
    run(state);
  }

  function clear() {
    state = null;
    unmount();
  }

  root.PhishGuardOverlay = { track, clear, levelOf };
})(typeof globalThis !== "undefined" ? globalThis : this);
