/* =====================================================================
   The chrome every page wears: the brand, the page tabs, the theme.

   This exists as one file rather than three copies because the three
   pages had drifted into three different navigations -- text links on
   two of them, a sidebar list on the third -- so moving between them was
   a different gesture depending on where you already were. The tabs are
   now the same control in the same place with the current page held
   down, and adding a page means editing one array.
   ===================================================================== */
"use strict";

const PAGES = [
  ["/console",  "Console",    "◈", "one package, traced end to end"],
  ["/explorer", "Explorer",   "◎", "confirmed threats and what they reach in your code"],
  ["/graph",    "Live graph", "⬡", "the whole graph, and npm as it publishes"],
];

/* The theme is a user decision, so it outlives the tab. `auto` is a real
   third state rather than the absence of a choice -- it means "follow the
   OS", which is not the same as "light". */
const THEME_KEY = "blastradius.theme";
const THEME_ORDER = ["auto", "light", "dark"];
const THEME_GLYPH = { auto: "◐", light: "○", dark: "●" };
const THEME_TITLE = {
  auto: "Theme: follows your system", light: "Theme: light", dark: "Theme: dark",
};

function readTheme() {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return THEME_ORDER.includes(v) ? v : "auto";
  } catch (e) { return "auto"; }
}

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* private mode */ }
  const btn = document.getElementById("themeBtn");
  if (btn) { btn.textContent = THEME_GLYPH[theme]; btn.title = THEME_TITLE[theme]; }
}

/* Applied before first paint by the inline call at the top of each page,
   so a dark-theme user never gets a white flash on load. */
applyTheme(readTheme());

/* Renders into whatever <header class="appbar"> the page provides, keeping
   any page-specific children (stat strips, action buttons) that were
   already there -- they are appended after the tabs. */
function mountChrome() {
  const bar = document.querySelector(".appbar");
  if (!bar) return;

  const here = location.pathname.replace(/\/$/, "") || "/console";
  const tabs = PAGES.map(([href, label, glyph, help]) => {
    const on = href === here || (here === "/" && href === "/console");
    return `<a href="${href}" title="${help}"${on ? ' aria-current="page"' : ""}
      ><span class="gl">${glyph}</span><span class="lb">${label}</span></a>`;
  }).join("");

  /* Styled by base.css, not inline. An inline `flex` would outrank every
     media query, so the wrapper could never be told to shrink on a
     phone -- which is exactly what pushed the theme button onto a line
     of its own. */
  const lead = document.createElement("div");
  lead.className = "bar-lead";
  lead.innerHTML =
    `<div class="brand"><span class="mark"></span>
       <span class="name">Blast Radius <em>/ ${pageName(here)}</em></span></div>
     <nav class="tabs" aria-label="Views">${tabs}</nav>`;
  bar.prepend(lead);

  /* On a narrow bar the tab strip scrolls, and the page you are on can
     start out scrolled past the right edge — so the one tab that has to
     be visible is the one that would not be. */
  lead.querySelector('.tabs a[aria-current="page"]')
    ?.scrollIntoView({ block: "nearest", inline: "center" });

  /* Drawers are anchored below the bar rather than to the top of the
     viewport, so an open panel never covers the tabs or its own dismiss
     button. The bar wraps to two rows on a phone, so its height is
     measured rather than assumed. */
  const trackBarHeight = () => document.documentElement.style
    .setProperty("--bar-top", bar.getBoundingClientRect().height + "px");
  trackBarHeight();
  if (window.ResizeObserver) new ResizeObserver(trackBarHeight).observe(bar);
  else window.addEventListener("resize", trackBarHeight);

  const theme = document.createElement("button");
  theme.className = "icon-btn";
  theme.id = "themeBtn";
  theme.setAttribute("aria-label", "Change theme");
  theme.onclick = () => {
    const next = THEME_ORDER[(THEME_ORDER.indexOf(readTheme()) + 1) % THEME_ORDER.length];
    applyTheme(next);
    /* The canvas caches its colours, so a theme change has to tell it.
       `data-theme` fires no event of its own, and the graph page listens
       for this one. */
    window.dispatchEvent(new CustomEvent("themechange", { detail: next }));
  };
  bar.append(theme);
  applyTheme(readTheme());
}

/* Write a number into an app-bar stat, and tell the stylesheet whether it
   is zero. Shared because all three pages have the same bar and the same
   rule: an alarm colour that is on when there is nothing to be alarmed
   about is not an alarm. */
window.setStat = function setStat(id, value) {
  const b = document.getElementById(id);
  if (!b) return;
  const text = value == null ? "—" : String(value);
  b.textContent = text;
  const cell = b.closest(".barstat");
  if (cell) cell.dataset.zero = String(text === "0" || text === "—");
};

function pageName(here) {
  const hit = PAGES.find(([href]) => href === here);
  return hit ? hit[1] : "Console";
}

/* =====================================================================
   Collapsing rails

   These are three-column analyst tools, and three readable columns do
   not fit below roughly 1150px. Squeezing them loses the rails AND the
   canvas, so past its breakpoint a rail becomes an overlay panel with a
   button in the app bar.

   Shared here because all three pages need the same behaviour and the
   same accidents are easy to make: forgetting to close the panel when
   the viewport grows back (leaving a fixed-position rail floating over
   a layout that already has room for it), leaving `body.rail-open` set
   when the last panel closes, or trapping the user with no Escape.

   `media` is the width at which the rail stops fitting. Above it the
   rail is an ordinary grid column and the button is not rendered.
   ===================================================================== */
const RAILS = [];

/* Queued rather than run on the spot. Pages call setupRail from a script
   at the end of <body>, which is still before DOMContentLoaded -- so at
   that moment mountChrome has not run and there is no .brand to anchor a
   left-hand button against. The first attempt silently inserted nothing
   and the button simply never appeared. */
window.setupRail = function setupRail(opts) {
  ready(() => mountRail(opts));
};

function mountRail({ el, side, label, glyph, media }) {
  const bar = document.querySelector(".appbar");
  if (!el || !bar) return null;

  const btn = document.createElement("button");
  btn.className = "railtoggle icon-btn";
  btn.type = "button";
  btn.title = label;
  btn.setAttribute("aria-label", label);
  btn.setAttribute("aria-expanded", "false");
  btn.textContent = glyph;
  // Left-hand rails get a button on the left of the bar, right-hand ones
  // on the right, so the control points at the thing it opens. The theme
  // button stays last on every page, so a right-hand toggle goes in
  // before it rather than after.
  const theme = document.getElementById("themeBtn");
  if (side === "left") bar.querySelector(".brand")?.before(btn);
  else if (theme) bar.insertBefore(btn, theme);
  else bar.append(btn);

  const mq = window.matchMedia(`(max-width: ${media}px)`);
  const rail = { el, btn, mq, side, open: false };
  RAILS.push(rail);

  btn.onclick = () => setRail(rail, !rail.open);
  mq.addEventListener("change", () => syncRail(rail));
  syncRail(rail);
  return rail;
}

function syncRail(rail) {
  const overlay = rail.mq.matches;
  rail.el.classList.toggle("as-drawer", overlay);
  rail.el.classList.toggle("from-left", overlay && rail.side === "left");
  rail.el.classList.toggle("from-right", overlay && rail.side === "right");
  rail.btn.style.display = overlay ? "grid" : "none";
  // Growing back past the breakpoint must not leave a fixed-position
  // panel floating over a layout that now has room for it inline.
  if (!overlay) setRail(rail, false);
  else rail.el.classList.toggle("open", rail.open);
}

function setRail(rail, open) {
  rail.open = open && rail.mq.matches;
  rail.el.classList.toggle("open", rail.open);
  rail.btn.setAttribute("aria-expanded", String(rail.open));
  // Only one panel at a time: two overlapping drawers on a phone leaves
  // no way to see what either is describing.
  if (rail.open) for (const other of RAILS) if (other !== rail) setRail(other, false);
  document.body.classList.toggle("rail-open", RAILS.some((r) => r.open));
  scrim().hidden = !RAILS.some((r) => r.open);
}

let _scrim = null;
function scrim() {
  if (!_scrim) {
    _scrim = document.createElement("div");
    _scrim.className = "scrim";
    _scrim.hidden = true;
    _scrim.onclick = () => RAILS.forEach((r) => setRail(r, false));
    document.body.append(_scrim);
  }
  return _scrim;
}

/* Close every open panel. Pages call this when an action inside a rail
   has answered the question the rail was opened to ask -- picking a
   threat, framing a finding -- because on a phone the panel is then
   covering the very thing it was asked to show. */
window.closeRails = () => RAILS.forEach((r) => setRail(r, false));

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") window.closeRails();
});

/* One queue, drained in call order, so mountChrome always builds the bar
   before anything tries to put a button in it. */
const PENDING = [];
function ready(fn) {
  if (document.readyState === "loading") PENDING.push(fn);
  else fn();
}
ready(mountChrome);
if (PENDING.length) {
  document.addEventListener("DOMContentLoaded", () => {
    while (PENDING.length) PENDING.shift()();
  });
}
