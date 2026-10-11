// Run with: node --test "tests/*.test.js"
// Layout and interaction regressions for the Gmail overlay, in headless Chrome with real time and
// trusted input (wheel, mouse, keyboard) over the DevTools protocol. Fixture:
// tests/browser/gmail-layout.html, where [role="main"] is tall content inside a separate scroll
// container under a fixed header. Skipped if Chrome isn't found (set CHROME_PATH).
const { test, before, after, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { findChrome, launch } = require("./browser/cdp.js");

const chromePath = findChrome();
const FIXTURE = pathToFileURL(path.join(__dirname, "browser", "gmail-layout.html")).href;
const skip = chromePath ? false : "Chrome not found (set CHROME_PATH)";
let page;

// Geometry of everything the tests reason about, in viewport coordinates.
const MEASURE = `(() => {
  const rect = el => { if (!el) return null; const r = el.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, left: r.left, right: r.right, width: r.width, height: r.height }; };
  const root = document.getElementById("phishguard-overlay-host")?.shadowRoot;
  const scroller = document.getElementById("scroller");
  const s = scroller.getBoundingClientRect();
  const scroll = root?.querySelector(".panel"); // the panel scrolls; its header is sticky
  return {
    pane: { top: s.top, bottom: Math.min(s.bottom, innerHeight), left: s.left, right: s.right, width: s.width },
    header: rect(document.getElementById("gmail-header")),
    subject: rect(document.querySelector("h2.hP")),
    subjectText: (() => { const r = document.createRange(); r.selectNodeContents(document.querySelector("h2.hP")); return rect(r); })(),
    controls: [...document.querySelectorAll(".ha .ctl")].map(rect),
    badge: rect(root?.querySelector(".badge")),
    badgeVisible: !!root && getComputedStyle(root.querySelector(".badge")).visibility === "visible",
    badgeText: root?.querySelector(".badge")?.textContent || "",
    panel: rect(root?.querySelector(".panel")),
    panelOpen: !!root && !root.querySelector(".panel").hidden,
    scroll: scroll ? { ...rect(scroll), scrollTop: scroll.scrollTop, scrollHeight: scroll.scrollHeight, clientHeight: scroll.clientHeight } : null,
    head: rect(root?.querySelector(".head")),
    score: rect(root?.querySelector(".score")),
    foot: rect(root?.querySelector(".foot")),
    action: rect(root?.querySelector(".action")),
    scrollerTop: scroller.scrollTop,
    focusOnBadge: root?.activeElement === root?.querySelector(".badge"),
    focusOnClose: root?.activeElement === root?.querySelector(".close")
  };
})()`;
const measure = () => page.evaluate(MEASURE);
const within = (inner, outer, slack = 0.5) =>
  inner.top >= outer.top - slack && inner.bottom <= outer.bottom + slack && inner.left >= outer.left - slack && inner.right <= outer.right + slack;
const overlaps = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
const center = r => [Math.round(r.left + r.width / 2), Math.round(r.top + r.height / 2)];

async function openFixture(width = 1280, height = 800) {
  await page.viewport(width, height);
  await page.goto(FIXTURE);
  await page.evaluate(`PhishGuardOverlay.track("layout", document.getElementById("msg"), () => longResult())`);
  await page.waitFor(`document.getElementById("phishguard-overlay-host")?.shadowRoot.querySelector(".badge.high")`);
  await page.frames();
}

async function openPanel() {
  const m = await measure();
  await page.click(...center(m.badge));
  await page.waitFor(`!document.getElementById("phishguard-overlay-host").shadowRoot.querySelector(".panel").hidden`);
  await page.frames();
}

// Wheel over a point until the scrolled element stops moving.
async function wheelUntilStable(x, y, read, deltaY = 240) {
  let last = -1;
  for (let i = 0; i < 40; i++) {
    await page.wheel(x, y, deltaY);
    await page.frames(2);
    const now = await read();
    if (now === last) return now;
    last = now;
  }
  return last;
}

before(async () => { if (chromePath) page = await launch(chromePath); });
after(async () => { if (page) await page.close(); });
beforeEach(() => { if (page) page.errors.length = 0; });

test("badge sits on the subject row, left of Gmail's controls, without covering the subject", { skip }, async () => {
  await openFixture();
  const m = await measure();
  assert.ok(m.badgeVisible);
  assert.match(m.badgeText, /High risk · 78%/);
  assert.ok(m.badge.top >= m.subject.top - 8 && m.badge.bottom <= m.subject.bottom + 8, "badge is level with the subject row");
  for (const control of m.controls) assert.ok(!overlaps(m.badge, control), "badge overlaps a Gmail control");
  assert.ok(!overlaps(m.badge, m.subjectText), "badge covers the subject text");
  assert.ok(within(m.badge, m.pane), "badge is outside the reading pane");
});

test("scrolling the email keeps the badge inside the reading pane, never over the header", { skip }, async () => {
  await openFixture();
  const start = await measure();
  const [x, y] = [Math.round(start.pane.left + 200), Math.round(start.pane.top + 300)];
  for (const target of [60, 400, 1500]) {
    await page.evaluate(`document.getElementById("scroller").scrollTo(0, ${target})`);
    await page.frames(3);
    const m = await measure();
    assert.ok(within(m.badge, m.pane), `scrollTop ${target}: badge ${JSON.stringify(m.badge)} outside pane ${JSON.stringify(m.pane)}`);
    assert.ok(!overlaps(m.badge, m.header), `scrollTop ${target}: badge overlaps the header`);
  }
  // Same with real wheel input.
  await page.evaluate(`document.getElementById("scroller").scrollTo(0, 0)`);
  await page.wheel(x, y, 700);
  await page.frames(4);
  const m = await measure();
  assert.ok(m.scrollerTop > 300, "the wheel scrolled the email");
  assert.ok(within(m.badge, m.pane) && !overlaps(m.badge, m.header), "badge left the pane after wheel scrolling");
});

test("the panel fits inside the visible pane at about two-thirds of its width", { skip }, async () => {
  await openFixture(1100, 800);
  await openPanel();
  const m = await measure();
  assert.ok(m.panelOpen);
  assert.ok(within(m.panel, m.pane), `panel ${JSON.stringify(m.panel)} outside pane ${JSON.stringify(m.pane)}`);
  const share = m.panel.width / m.pane.width;
  assert.ok(share >= 0.6 && share <= 0.7, `panel is ${Math.round(share * 100)}% of the pane width`);
  assert.ok(!overlaps(m.panel, m.header));
});

test("the panel's content scrolls all the way to the recommended action", { skip }, async () => {
  for (const [width, height] of [[1280, 800], [1280, 520], [900, 420]]) {
    await openFixture(width, height);
    await openPanel();
    let m = await measure();
    assert.ok(within(m.panel, m.pane), `${width}x${height}: panel outside the pane`);
    assert.ok(m.scroll.scrollHeight > m.scroll.clientHeight, `${width}x${height}: fixture should need scrolling`);
    const scrollerBefore = m.scrollerTop;
    await wheelUntilStable(...center(m.panel), () => page.evaluate(`document.getElementById("phishguard-overlay-host").shadowRoot.querySelector(".panel").scrollTop`));
    m = await measure();
    assert.ok(m.scroll.scrollTop + m.scroll.clientHeight >= m.scroll.scrollHeight - 1, `${width}x${height}: panel didn't reach the end`);
    // At the end, the whole recommended action and the footer are visible below the sticky header.
    assert.ok(m.action.top >= m.head.bottom - 1 && m.action.bottom <= m.panel.bottom + 1, `${width}x${height}: recommended action not fully visible`);
    assert.ok(m.foot.bottom <= m.panel.bottom + 1 && m.foot.top >= m.head.bottom - 1, `${width}x${height}: footer not visible`);
    assert.ok(m.head.top >= m.panel.top - 1, `${width}x${height}: header scrolled away`);
    assert.ok(m.action.bottom <= m.pane.bottom, `${width}x${height}: recommended action below the visible pane`);
    assert.equal(m.scrollerTop, scrollerBefore, `${width}x${height}: wheeling the panel scrolled the email behind it`);
  }
});

test("the open panel stays inside the pane while the email scrolls behind it", { skip }, async () => {
  await openFixture(1280, 700);
  await openPanel();
  await page.evaluate(`document.getElementById("scroller").scrollTo(0, 900)`);
  await page.frames(3);
  const m = await measure();
  assert.ok(m.panelOpen, "scrolling must not close the panel");
  assert.ok(within(m.panel, m.pane), `panel ${JSON.stringify(m.panel)} outside pane ${JSON.stringify(m.pane)}`);
  assert.ok(!overlaps(m.panel, m.header));
});

test("trusted clicks: inside keeps the panel open, outside closes it without stealing focus", { skip }, async () => {
  await openFixture();
  await openPanel();
  let m = await measure();
  assert.ok(m.focusOnClose, "opening focuses the close button");

  // Only points that are actually visible inside the panel.
  await page.click(...center(m.score));
  await page.click(Math.round(m.panel.left + 30), Math.round(m.head.top + 20)); // header area
  await page.click(Math.round(m.panel.right - 4), Math.round(m.head.bottom + 40)); // on the scrollbar
  await page.click(Math.round(m.panel.left + 40), Math.round(m.panel.bottom - 30)); // lower content
  m = await measure();
  assert.ok(m.panelOpen, "an inside click closed the panel");

  await page.click(Math.round(m.pane.left + 120), Math.round(m.pane.bottom - 40)); // email text
  m = await measure();
  assert.ok(!m.panelOpen, "an outside click didn't close the panel");
  assert.ok(m.badgeVisible);
  assert.ok(!m.focusOnBadge, "an outside click moved focus to the badge");

  await page.click(Math.round(m.header.left + 300), Math.round(m.header.top + 30)); // header, while collapsed
  m = await measure();
  assert.ok(!m.panelOpen && m.badgeVisible, "an outside click while collapsed changed the overlay");
});

test("Escape and the close button collapse the panel and return focus to the badge", { skip }, async () => {
  await openFixture();
  await openPanel();
  await page.key("Escape", "Escape", 27);
  let m = await measure();
  assert.ok(!m.panelOpen, "Escape didn't close the panel");
  assert.ok(m.focusOnBadge, "Escape didn't return focus to the badge");

  await openPanel();
  m = await measure();
  const close = await page.evaluate(`(() => { const r = document.getElementById("phishguard-overlay-host").shadowRoot.querySelector(".close").getBoundingClientRect(); return [Math.round(r.left + r.width / 2), Math.round(r.top + r.height / 2)]; })()`);
  await page.click(...close);
  m = await measure();
  assert.ok(!m.panelOpen, "the close button didn't close the panel");
  assert.ok(m.focusOnBadge, "the close button didn't return focus to the badge");

  await openPanel(); // and it reopens
  assert.ok((await measure()).panelOpen);
  assert.deepEqual(page.errors, []);
});
