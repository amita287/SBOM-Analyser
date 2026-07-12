/* ==========================================================================
   SBOM Analyzer — shared console runtime.

   Every page imports this, so they cannot drift on what a severity is called,
   how a score is rounded, what the sidebar says, or what happens when the API
   is down.

   No build step, no framework, no bundler. Three pages and a graph do not need
   200KB of runtime to render a table. ES modules, served straight.
   ========================================================================== */

/* Same-origin when served from FastAPI (/static/*). Override for a dev server
   on another port with ?api=http://127.0.0.1:8000 */
export const API =
  new URLSearchParams(location.search).get("api")?.replace(/\/$/, "") ?? "";

export const SEVERITIES = ["critical", "high", "medium", "low", "none"];

/* Kept in lockstep with console.css. Cytoscape paints to a canvas and cannot
   read a CSS custom property, so the hexes must also exist here. This is the
   one intentional duplication in the project — flagged loudly in both files. */
export const SEV_HEX = {
  critical: "#e5484d",
  high: "#e07b39",
  medium: "#d4a017",
  low: "#30a46c",
  none: "#5b6b7f",
};

/* The dataset's taxonomy. `none` is its word for "clean" — the UI says "Clean",
   because that is what a human calls it, but the wire value is `none` and every
   filter must use it. */
export const RISK_TYPES = [
  ["vulnerable_dependency", "Vulnerable"],
  ["transitive_vulnerability", "Transitive"],
  ["license_conflict", "Licence conflict"],
  ["transitive_license_conflict", "Licence (transitive)"],
  ["license_unknown", "Licence unknown"],
  ["unmaintained", "Unmaintained"],
  ["none", "Clean"],
];

export const CLEAN = "none";
export const RISK_LABEL = Object.fromEntries(RISK_TYPES);

/* -------------------------------------------------------------------------- */
/* Icons — inline, 16px, 1.6 stroke. No icon font, no sprite sheet, no CDN.    */
/* -------------------------------------------------------------------------- */
const P = (d) =>
  `<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;

export const ICON = {
  shield: P('<path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z"/>'),
  grid: P('<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>'),
  apps: P('<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 9v11"/>'),
  graph: P('<circle cx="6" cy="6" r="2.4"/><circle cx="18" cy="8" r="2.4"/><circle cx="9" cy="18" r="2.4"/><path d="M7.9 7.4l8.4 .2M7.3 8l1.2 7.7"/>'),
  list: P('<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>'),
  file: P('<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z"/><path d="M14 3v5h5"/>'),
  code: P('<path d="M9 8l-4 4 4 4M15 8l4 4-4 4"/>'),
  book: P('<path d="M4 5a2 2 0 012-2h13v18H6a2 2 0 01-2-2V5z"/><path d="M8 3v18"/>'),
  down: P('<path d="M12 4v11M7.5 11l4.5 4.5 4.5-4.5M5 20h14"/>'),
  search: P('<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4 4"/>'),
  check: P('<path d="M20 6L9.5 17 4 11.5"/>'),
  arrow: P('<path d="M5 12h13M13 6l6 6-6 6"/>'),
  back: P('<path d="M19 12H6M11 6l-6 6 6 6"/>'),
  refresh: P('<path d="M20 11a8 8 0 10-1.5 5.5M20 5v6h-6"/>'),
  chev: P('<path d="M9 6l6 6-6 6"/>'),
  alert: P('<path d="M12 8v5M12 16.5h.01"/><path d="M10.3 3.9L2.6 17.2A2 2 0 004.3 20h15.4a2 2 0 001.7-2.8L13.7 3.9a2 2 0 00-3.4 0z"/>'),
  bug: P('<path d="M9 6a3 3 0 016 0M6 10h12v4a6 6 0 01-12 0v-4zM4 12H2M22 12h-2M5 6l2 2M19 6l-2 2M5 19l2.5-2M19 19l-2.5-2"/>'),
  scale: P('<path d="M12 4v16M7 20h10M5 8h14M5 8l-2.5 6h5L5 8zM19 8l-2.5 6h5L19 8z"/>'),
  clock: P('<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>'),
  sun: P('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
  moon: P('<path d="M20 14.5A8.5 8.5 0 019.5 4a8.5 8.5 0 1010.5 10.5z"/>'),
  upload: P('<path d="M12 16V4M7.5 8.5L12 4l4.5 4.5"/><path d="M4 15v3a2 2 0 002 2h12a2 2 0 002-2v-3"/>'),
};

/* -------------------------------------------------------------------------- */
/* Fetch                                                                       */
/* -------------------------------------------------------------------------- */
export async function api(path) {
  const res = await fetch(`${API}${path}`, { headers: { accept: "application/json" } });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* a non-JSON error body is still an error; keep the status text */
    }
    throw new Error(`${res.status} — ${detail}`);
  }
  return res.json();
}

/* -------------------------------------------------------------------------- */
/* Format                                                                      */
/* -------------------------------------------------------------------------- */
export const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

/* Scores are 0–100 floats. One decimal is more precision than a human needs and
   less than the score carries; round, and never imply otherwise. */
export const score = (n) => Math.round(Number(n) || 0);

export const sevBadge = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;

export const plural = (n, one, many) => `${n} ${n === 1 ? one : (many ?? one + "s")}`;

/* A dependency can hold several risk types at once (vulnerable AND unmaintained).
   Order them worst-first, so a tag row reads the way a human triages. */
const RISK_ORDER = RISK_TYPES.map(([k]) => k);
export const sortRiskTypes = (t) =>
  [...(t ?? [])].sort((a, b) => RISK_ORDER.indexOf(a) - RISK_ORDER.indexOf(b));

export const riskTags = (t) =>
  sortRiskTypes(t).map((x) => `<span class="tag">${esc(RISK_LABEL[x] ?? x)}</span>`).join("");

export const initials = (name) =>
  String(name || "?")
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join("");

/* Deterministic hue per owner, so the same person is the same colour on every
   page and across reloads. No randomness anywhere in this project — not even
   in an avatar. */
export function avatarColor(seed) {
  let h = 0;
  for (const ch of String(seed || "")) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return `hsl(${h} 22% 30%)`;
}

export const who = (owner) =>
  `<span class="who"><span class="av" style="--av:${avatarColor(owner)}">${esc(initials(owner))}</span>${esc(owner ?? "—")}</span>`;

/* -------------------------------------------------------------------------- */
/* Export                                                                      */
/*                                                                             */
/* Built in the browser from data already fetched — no new backend surface, and */
/* what you download is exactly what you were looking at.                       */
/* -------------------------------------------------------------------------- */

/* RFC 4180. Quote every field: library names and remediation prose contain
   commas, quotes and newlines, and a CSV that corrupts on the first comma is
   worse than no CSV at all. */
const cell = (v) => {
  if (v === null || v === undefined) return '""';
  const s = Array.isArray(v) ? v.join(" | ") : String(v);
  return `"${s.replace(/"/g, '""')}"`;
};

export const toCSV = (rows, cols) =>
  [
    cols.map((c) => cell(c.header)).join(","),
    ...rows.map((r) => cols.map((c) => cell(c.get(r))).join(",")),
  ].join("\r\n");

export function download(filename, text, mime = "text/csv;charset=utf-8") {
  /* A BOM, so Excel on Windows opens UTF-8 without mangling every non-ASCII
     character. The people who read this file use Excel. */
  const bom = mime.startsWith("text/csv") ? "﻿" : "";
  const url = URL.createObjectURL(new Blob([bom + text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  toast(`Exported ${filename}`);
}

export function toast(msg) {
  document.querySelector(".toast")?.remove();
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = `${ICON.check}<span>${esc(msg)}</span>`;
  document.body.append(el);
  setTimeout(() => el.remove(), 3200);
}

/* The columns a findings export carries. Everything a reader would need to act
   on a row without opening this UI again — including whether the prose was
   written by a model or a template. */
export const FINDING_COLS = [
  { header: "dependency_id", get: (f) => f.dependency_id },
  { header: "app_id", get: (f) => f.app_id },
  { header: "library", get: (f) => f.library_name },
  { header: "version", get: (f) => f.version },
  { header: "dependency_type", get: (f) => f.dependency_type },
  { header: "license", get: (f) => f.license },
  { header: "license_outcome", get: (f) => f.license_outcome },
  { header: "risk_score", get: (f) => score(f.risk_score) },
  { header: "severity", get: (f) => f.severity },
  { header: "risk_types", get: (f) => sortRiskTypes(f.risk_types) },
  { header: "primary_risk_type", get: (f) => f.primary_risk_type },
  { header: "vuln_status", get: (f) => f.vuln_status },
  { header: "cves_confirmed", get: (f) => f.matched_cves.filter((c) => c.confidence === "confirmed").map((c) => c.cve_id) },
  { header: "cves_unconfirmed", get: (f) => f.matched_cves.filter((c) => c.confidence !== "confirmed").map((c) => c.cve_id) },
  { header: "max_cvss", get: (f) => (f.matched_cves.length
      ? Math.max(...f.matched_cves.map((c) => c.cvss_score)).toFixed(1) : "") },
  { header: "patch_available", get: (f) => f.matched_cves.some((c) => c.patch_available) },
  { header: "fixed_versions", get: (f) => f.matched_cves.filter((c) => c.fixed_version).map((c) => c.fixed_version) },
  { header: "attack_paths", get: (f) => (f.attack_paths ?? []).length },
  { header: "last_updated", get: (f) => f.maintenance?.last_updated ?? "" },
  { header: "age_years", get: (f) => f.maintenance?.age_years?.toFixed(1) ?? "" },
  { header: "is_stale", get: (f) => f.maintenance?.is_stale ?? "" },
  { header: "remediation_priority", get: (f) => f.remediation?.priority ?? "" },
  { header: "remediation_steps", get: (f) => f.remediation?.steps ?? [] },
  { header: "prose_source", get: (f) => (f.llm_enriched ? "llm" : "template") },
];

export const APP_COLS = [
  { header: "app_id", get: (a) => a.app_id },
  { header: "name", get: (a) => a.name },
  { header: "owner", get: (a) => a.owner ?? "" },
  { header: "environment", get: (a) => a.environment ?? "" },
  { header: "business_criticality", get: (a) => a.business_criticality },
  { header: "license_model", get: (a) => a.license_model ?? "" },
  { header: "language", get: (a) => a.language ?? "" },
  { header: "department", get: (a) => a.department ?? "" },
  { header: "app_score", get: (a) => score(a.app_score) },
  { header: "severity", get: (a) => a.severity },
  { header: "dependencies", get: (a) => a.findings.length },
  { header: "at_risk", get: (a) => a.findings.filter((f) => !f.risk_types.includes(CLEAN)).length },
  { header: "vulnerable", get: (a) => a.findings.filter((f) => f.matched_cves.length).length },
  { header: "attack_paths", get: (a) => a.findings.reduce((n, f) => n + (f.attack_paths?.length ?? 0), 0) },
];

/* -------------------------------------------------------------------------- */
/* Faults                                                                      */
/* -------------------------------------------------------------------------- */
export function fault(el, err) {
  el.innerHTML = `
    <div class="fault">
      <b>Can't reach the analyzer.</b> ${esc(err.message)}
      <div style="margin-top:8px;color:#d5a5a7">
        Is the API up? <code>uvicorn sbom_analyzer.api.main:app --reload</code><br>
        If it's on another port, append <code>?api=http://127.0.0.1:8000</code> to this page's URL.
      </div>
    </div>`;
}

/* -------------------------------------------------------------------------- */
/* Shell                                                                       */
/* -------------------------------------------------------------------------- */
const NAV = [
  ["overview", "dashboard.html", "grid", "Overview"],
  ["apps", "applications.html", "apps", "Applications"],
  ["graph", "graph.html", "graph", "Dependency graph"],
  ["findings", "findings.html", "list", "Findings"],
  ["upload", "upload.html", "upload", "Upload SBOM"],
];

export function shell(page) {
  const item = ([id, href, icon, label]) =>
    `<a class="nav" href="${href}"${id === page ? ' aria-current="page"' : ""}>
       ${ICON[icon]}<span>${label}</span>
     </a>`;

  return `
    <aside class="rail">
      <div class="org">
        <span class="mark">${ICON.shield}</span>
        <span class="txt">
          <div class="n">SBOM Analyzer</div>
          <div class="s" id="rail-run">—</div>
        </span>
      </div>

      <button class="railsearch" id="railsearch">
        ${ICON.search}<span>Search anything…</span><kbd class="k">/</kbd>
      </button>

      <div class="railgroup">Analysis</div>
      ${NAV.map(item).join("")}

      <div class="railgroup">Artifacts</div>
      <a class="nav" href="${API}/runs/latest/report.html" target="_blank" rel="noopener">
        ${ICON.file}<span>HTML report</span><span class="ext">↗</span>
      </a>
      <a class="nav" href="${API}/runs/latest/report" target="_blank" rel="noopener">
        ${ICON.code}<span>analysis.json</span><span class="ext">↗</span>
      </a>
      <a class="nav" href="${API}/docs" target="_blank" rel="noopener">
        ${ICON.book}<span>API docs</span><span class="ext">↗</span>
      </a>

      <div class="railfill"></div>
      <button class="themebtn" id="themebtn"></button>
      <div class="provcard" id="provcard"></div>
    </aside>`;
}

/* The sidebar's provenance card. The reference design puts a plan upsell here.
   This project's central claim is that no model ever produces a number, so the
   corner of every screen states, permanently, how the run was produced. If the
   LLM contributed nothing, it says so rather than quietly implying otherwise. */
export function provcard(run) {
  const off = !run.llm_provider || run.llm_provider === "none";
  const allFellBack = run.llm_calls > 0 && run.llm_calls === run.llm_fallbacks;

  const prose = off
    ? `<b>templated</b>`
    : allFellBack
      ? `<b class="warn">fell back</b>`
      : `<b>${esc(run.llm_provider)}</b>`;

  document.getElementById("rail-run").textContent = run.run_id;

  return `
    <div class="h"><span class="dot"></span>Run provenance</div>
    <dl>
      <div class="r"><span>Scores</span><b class="good">deterministic</b></div>
      <div class="r"><span>Prose</span>${prose}</div>
      <div class="r"><span>LLM calls</span><b>${run.llm_calls}</b></div>
      <div class="r"><span>As of</span><b>2026-04-15</b></div>
    </dl>`;
}

export function topbar({ title, icon = "grid", crumb = "", right = "" }) {
  return `
    <div class="title">
      ${ICON[icon]}
      <span>${title}</span>
      ${crumb ? `<span class="crumb">/ ${crumb}</span>` : ""}
    </div>
    <div class="right">${right}</div>`;
}

/* Dropdown that closes on outside click and on Escape, like every other menu a
   person has ever used. */
export function dropdown(btn, sheet) {
  const close = () => (sheet.hidden = true);
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    sheet.hidden = !sheet.hidden;
  });
  document.addEventListener("click", close);
  addEventListener("keydown", (e) => e.key === "Escape" && close());
  sheet.addEventListener("click", (e) => e.stopPropagation());
}

/* -------------------------------------------------------------------------- */
/* Polling                                                                     */
/* -------------------------------------------------------------------------- */

/* Refresh on an interval, but pause while the tab is hidden — a backgrounded
   dashboard hammering the API for nobody's benefit is just heat. Refetch on
   return, so you never read a stale screen you can't tell is stale. */
export function poll(fn, ms) {
  let t = null;
  const stop = () => t && clearInterval(t);
  const start = () => { stop(); t = setInterval(fn, ms); };
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return stop();
    fn();
    start();
  });
  fn();
  start();
}

/* "Updated 12s ago" beats a spinner: it tells you how much to trust what you are
   looking at, which is the only thing a refresh indicator is for. */
export function ticker(el, getLast) {
  setInterval(() => {
    const at = getLast();
    if (!at) return;
    const s = Math.round((Date.now() - at) / 1000);
    el.textContent = s < 5 ? "updated just now" : `updated ${s}s ago`;
  }, 1000);
}

/* ==========================================================================
   Theme
   ========================================================================== */

/* Cytoscape paints to a canvas and cannot read a CSS custom property, so the
   graph needs real hex. Read them off the live stylesheet rather than keeping a
   second hard-coded copy that silently rots — the whole point of a theme is that
   these values move. */
export function severityHex() {
  const root = getComputedStyle(document.documentElement);
  const read = (name, fallback) =>
    (root.getPropertyValue(name) || "").trim() || fallback;
  return {
    critical: read("--sev-critical", SEV_HEX.critical),
    high: read("--sev-high", SEV_HEX.high),
    medium: read("--sev-medium", SEV_HEX.medium),
    low: read("--sev-low", SEV_HEX.low),
    none: read("--sev-none", SEV_HEX.none),
  };
}

export function chromeHex() {
  const root = getComputedStyle(document.documentElement);
  const read = (n, f) => (root.getPropertyValue(n) || "").trim() || f;
  return {
    ink2: read("--ink-2", "#9b9fa6"),
    line: read("--line-strong", "#2e3236"),
    panel: read("--panel", "#131416"),
    panel3: read("--panel-3", "#202327"),
    accent: read("--accent", "#8091f5"),
  };
}

const THEME_KEY = "sbom.theme";

export const currentTheme = () =>
  document.documentElement.dataset.theme === "light" ? "light" : "dark";

export function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* private mode: the choice just won't persist. Not worth failing over. */
  }
  // The graph repaints from real hex, so it has to be told.
  dispatchEvent(new CustomEvent("themechange", { detail: { theme } }));
}

/* Runs before first paint (inlined in each page's <head>) so the console never
   flashes dark-then-light. Falls back to the OS preference. */
export function initTheme() {
  let saved = null;
  try {
    saved = localStorage.getItem(THEME_KEY);
  } catch {
    /* ignore */
  }
  const os =
    typeof matchMedia === "function" &&
    matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  document.documentElement.dataset.theme = saved || os;
}

function wireThemeToggle() {
  const btn = document.getElementById("themebtn");
  if (!btn) return;
  const paint = () => {
    const t = currentTheme();
    btn.innerHTML =
      (t === "light" ? ICON.moon : ICON.sun) +
      `<span>${t === "light" ? "Dark" : "Light"} theme</span>` +
      `<span class="state">${t}</span>`;
  };
  btn.addEventListener("click", () => {
    applyTheme(currentTheme() === "light" ? "dark" : "light");
    paint();
  });
  paint();
}

/* ==========================================================================
   Command palette — the sidebar search
   ==========================================================================
   It used to be a button that navigated to the findings page. That is not a
   search; it is a redirect wearing a search's clothes. This indexes the run once
   and matches applications, libraries, dependency ids, licences and CVE ids, then
   jumps straight to the row.
   ========================================================================== */
let paletteIndex = null;

async function buildIndex() {
  if (paletteIndex) return paletteIndex;
  const rep = await api("/runs/latest/report");

  const items = [];
  for (const app of rep.apps) {
    items.push({
      kind: "app",
      label: app.name,
      sub: `${app.app_id} · ${app.findings.length} dependencies`,
      href: `app.html?id=${encodeURIComponent(app.app_id)}`,
      hay: `${app.name} ${app.app_id}`.toLowerCase(),
      score: app.app_score,
    });

    for (const f of app.findings) {
      const cves = f.matched_cves.map((c) => c.cve_id).join(" ");
      items.push({
        kind: f.is_risk ? "risk" : "dep",
        label: `${f.library_name} ${f.version}`,
        sub: `${f.dependency_id} · ${app.name}${cves ? ` · ${cves}` : ""}`,
        href: `app.html?id=${encodeURIComponent(f.app_id)}&dep=${encodeURIComponent(
          f.dependency_id,
        )}`,
        hay: `${f.library_name} ${f.version} ${f.dependency_id} ${f.license} ${cves}`.toLowerCase(),
        score: f.risk_score,
      });
    }
  }
  paletteIndex = items;
  return items;
}

function wirePalette() {
  document.body.insertAdjacentHTML(
    "beforeend",
    `<div class="palette" id="palette" hidden>
       <div class="pal-box" role="dialog" aria-label="Search">
         <div class="pal-input">
           ${ICON.search}
           <input id="pal-q" type="text" autocomplete="off" spellcheck="false"
                  placeholder="Search applications, libraries, CVE ids…">
           <kbd>esc</kbd>
         </div>
         <div class="pal-results" id="pal-results"></div>
       </div>
     </div>`,
  );

  const box = document.getElementById("palette");
  const input = document.getElementById("pal-q");
  const out = document.getElementById("pal-results");
  let rows = [];
  let cursor = 0;

  const close = () => {
    box.hidden = true;
    input.value = "";
    out.innerHTML = "";
  };

  const open = async () => {
    box.hidden = false;
    input.focus();
    try {
      await buildIndex();
      render();
    } catch (err) {
      out.innerHTML = `<div class="pal-empty">Can't reach the analyzer — ${esc(
        err.message,
      )}</div>`;
    }
  };

  const render = () => {
    const q = input.value.trim().toLowerCase();
    if (!q) {
      rows = [];
      out.innerHTML =
        `<div class="pal-empty">Type to search — an app name, a library, ` +
        `a dependency id, or a CVE.</div>`;
      return;
    }

    /* Applications first, then risky dependencies by score, then clean ones. A
       search that buries the app you just named under forty of its own libraries
       is not being helpful. */
    const rank = { app: 0, risk: 1, dep: 2 };
    rows = (paletteIndex ?? [])
      .filter((it) => it.hay.includes(q))
      .sort((a, b) =>
        rank[a.kind] !== rank[b.kind]
          ? rank[a.kind] - rank[b.kind]
          : (b.score ?? 0) - (a.score ?? 0),
      )
      .slice(0, 40);

    cursor = 0;
    out.innerHTML = rows.length
      ? rows
          .map(
            (it, i) => `
              <button class="pal-row ${i === 0 ? "on" : ""}" data-i="${i}">
                <span class="pal-kind ${it.kind}">${it.kind}</span>
                <span class="pal-label">${esc(it.label)}</span>
                <span class="pal-sub">${esc(it.sub)}</span>
              </button>`,
          )
          .join("")
      : `<div class="pal-empty">No match for "${esc(input.value)}".</div>`;
  };

  const move = (d) => {
    if (!rows.length) return;
    cursor = (cursor + d + rows.length) % rows.length;
    out
      .querySelectorAll(".pal-row")
      .forEach((r, i) => r.classList.toggle("on", i === cursor));
    out.querySelector(".pal-row.on")?.scrollIntoView({ block: "nearest" });
  };

  const go = (i) => {
    if (rows[i]) location.href = rows[i].href;
  };

  input.addEventListener("input", render);
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Enter") { e.preventDefault(); go(cursor); }
    else if (e.key === "Escape") close();
  });
  out.addEventListener("click", (e) => {
    const row = e.target.closest(".pal-row");
    if (row) go(Number(row.dataset.i));
  });
  box.addEventListener("click", (e) => {
    if (e.target === box) close();
  });

  document.getElementById("railsearch")?.addEventListener("click", open);
  addEventListener("keydown", (e) => {
    const typing = /input|textarea|select/i.test(e.target.tagName);
    if ((e.key === "/" && !typing) || (e.key === "k" && (e.metaKey || e.ctrlKey))) {
      e.preventDefault();
      open();
    }
  });

  render();
}

/* Wired up by every page immediately after `shell()` puts the rail in the DOM. */
export function initChrome() {
  wireThemeToggle();
  wirePalette();
}
