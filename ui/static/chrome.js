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
      ><span class="gl">${glyph}</span>${label}</a>`;
  }).join("");

  const lead = document.createElement("div");
  lead.style.cssText = "display:flex;align-items:center;gap:14px;flex:none";
  lead.innerHTML =
    `<div class="brand"><span class="mark"></span>
       <span class="name">Blast Radius <em>/ ${pageName(here)}</em></span></div>
     <nav class="tabs" aria-label="Views">${tabs}</nav>`;
  bar.prepend(lead);

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

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", mountChrome);
} else {
  mountChrome();
}
