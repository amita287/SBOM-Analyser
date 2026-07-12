/* ==========================================================================
   The expandable finding row.

   Shared by applications drill-down (app.html) and the findings explorer
   (findings.html) so a CVE looks and reads identically wherever you meet it.
   ========================================================================== */

import { esc, score, sevBadge, riskTags, plural, ICON, API } from "./console.js";

/* Exploitability is now a property of the ADVISORY, not of our code. The old
   dataset told us whether our code called the vulnerable function; this one
   publishes an exploitability rating on the CVE itself. Different question, so
   the wording has to change with it — "imports only" would be a lie here. */
export const EXPLOIT_TEXT = {
  high: "high exploitability",
  medium: "medium exploitability",
  low: "low exploitability",
  none: "not exploitable",
};

/* ---------------------------------------------------------------- CVE card */
function cveCard(c, version) {
  const tone = `var(--sev-${
    c.cvss_severity === "critical" ? "critical"
    : c.cvss_severity === "high" ? "high"
    : c.cvss_severity === "medium" ? "medium"
    : "low"
  })`;

  const cls =
    c.exploitability === "high" ? "calls"
    : c.exploitability === "medium" ? "imports"
    : "";

  /* A `potential` match means the library matched but this version is NOT in the
     advisory's affected list. It is still shown — a reviewer needs to see it —
     but struck through and captioned, so the report never *asserts* a
     vulnerability the advisory itself does not support. */
  const unconfirmed = c.confidence !== "confirmed";

  return `
    <div class="cve ${c.dismissed ? "fp dismissed" : unconfirmed ? "fp" : ""}" style="--tone:${tone}">
      <div class="top">
        <span class="cid">${esc(c.cve_id)}</span>
        <span class="cvss">${c.cvss_score.toFixed(1)} ${esc(c.cvss_severity)}</span>
      </div>
      <div class="lines">
        <div><span class="k">Affects</span> <code>${esc((c.affected_versions ?? []).join(", ") || "—")}</code></div>
        ${c.description
          ? `<div><span class="k">Detail</span> ${esc(c.description)}</div>`
          : ""}
        <div><span class="k">Fix</span> ${
          c.patch_available && c.fixed_version
            ? `upgrade to <code>${esc(c.fixed_version)}</code>`
            : `<span style="color:var(--sev-high)">no patch available</span>`
        }</div>
        ${c.exploitability
          ? `<div style="margin-top:3px"><span class="exploit ${cls}">${esc(
              EXPLOIT_TEXT[c.exploitability] ?? c.exploitability,
            )}</span></div>`
          : ""}
      </div>
      ${c.dismissed
        ? `<div class="fp-note"><b>Dismissed by adjudication.</b>
             <span>${esc(c.adjudication ?? "")}</span></div>`
        : unconfirmed
          ? `<div class="fp-note"><b>Potential — unconfirmed.</b>
               <span>The library matches this advisory, but version
               <b>${esc(version)}</b> is not in its affected list. An advisory's list
               is not proof of safety (backports and vendor patch levels fall outside
               it), so this is kept for review at reduced weight.${
                 c.adjudication ? ` <i>${esc(c.adjudication)}</i>` : ""
               }</span></div>`
          : ""}
    </div>`;
}

/* -------------------------------------------------------------- attack path */
function pathCard(p, label) {
  const hops = p.path
    .map((id, i) => {
      const cls = i === 0 ? "root" : i === p.path.length - 1 ? "term" : "";
      return `<span class="hop ${cls}" title="${esc(id)}">${esc(label(id))}</span>`;
    })
    .join('<span class="arr">▶</span>');

  const n = p.path.length - 2; // hops between the app and the vulnerable dep
  return `
    <div class="path">
      <div class="hops">${hops}</div>
      <div class="via">
        ${n <= 0 ? "direct dependency" : `${plural(n, "hop")} deep`}
        ${p.cve_id ? ` · <b>${esc(p.cve_id)}</b>` : ""}
      </div>
    </div>`;
}

/* Who wrote the prose — a model, or a deterministic template.
   Shown ONLY when a model actually did. The template case is silent here: it was
   repeating on every expanded row and saying nothing new.

   That silence is not a cover-up. The run-level provenance card in the sidebar
   states it once, permanently ("Prose: templated"), which is the honest place for
   a fact that is true of the entire run. What must never happen is the reverse —
   template prose *presented* as a model's reasoning — and that is still
   impossible: this line only ever appears when `llm_enriched` is true. */
const proseSource = (f) =>
  f.llm_enriched
    ? `<div class="prose-src"><i></i>Written by the configured LLM.</div>`
    : "";

/* --------------------------------------------------------------- the detail */
export function findingDetail(f, { label }) {
  const live = f.matched_cves.filter((c) => c.confidence === "confirmed");
  const fps = f.matched_cves.filter((c) => c.confidence !== "confirmed");
  const paths = f.attack_paths ?? [];
  const m = f.maintenance;

  const licClass =
    f.license_outcome === "conflict" ? "bad"
    : f.license_outcome === "unknown" ? "warn"
    : "ok";

  return `
    <div class="detail">
      <div class="dcols">
        <section>
          <h4>Dependency</h4>
          <dl class="kv">
            <dt>Id</dt><dd class="mono">${esc(f.dependency_id)}</dd>
            <dt>Type</dt><dd>${esc(f.dependency_type)}</dd>
            <dt>Licence</dt><dd>${f.license ? esc(f.license) : "<i>unknown</i>"}</dd>
            <dt>Outcome</dt><dd class="${licClass}">${esc(f.license_outcome)}</dd>
            ${m ? `
              <dt>Updated</dt><dd>${esc(m.last_updated)}</dd>
              <dt>Age</dt><dd class="${m.is_stale ? "warn" : "ok"}">
                ${m.age_years.toFixed(1)} yrs${m.is_stale ? " — stale" : ""}</dd>` : ""}
          </dl>
          ${f.remediation ? `
            <h4 style="margin-top:16px">
              Remediation
              <span class="prio prio-${esc(f.remediation.priority)}">${esc(f.remediation.priority)}</span>
            </h4>
            <ol class="steps">
              ${f.remediation.steps.map((s) => `<li>${esc(s)}</li>`).join("")}
            </ol>` : ""}
        </section>

        <section>
          ${live.length || fps.length ? `
            <h4>${plural(live.length, "confirmed CVE")}${fps.length ? ` · ${fps.length} unconfirmed` : ""}</h4>
            ${[...live, ...fps].map((c) => cveCard(c, f.version)).join("")}` : `
            <h4>CVEs</h4>
            <p class="none">No advisory matches this version.</p>`}
        </section>

        <section>
          ${paths.length ? `
            <h4>${plural(paths.length, "attack path")}</h4>
            ${paths.map((p) => pathCard(p, label)).join("")}` : ""}

          ${f.narrative ? `
            <h4 style="${paths.length ? "margin-top:16px" : ""}">Attack chain</h4>
            <div class="narrative">${esc(f.narrative)}</div>` : ""}

          ${f.narrative || f.remediation ? proseSource(f) : ""}

          <a class="btn" style="margin-top:14px"
             href="graph.html?app=${encodeURIComponent(f.app_id)}&node=${encodeURIComponent(f.dependency_id)}">
            ${ICON.graph}<span>Show in graph</span>
          </a>
        </section>
      </div>
    </div>`;
}

/* ------------------------------------------------------------------ the row */
export function findingRow(f, { showApp = false, appName = () => "" } = {}) {
  const live = f.matched_cves.length;
  const worst = f.matched_cves.reduce((mx, c) => Math.max(mx, c.cvss_score), 0);
  const anyConfirmed = f.matched_cves.some((c) => c.confidence === "confirmed");

  return `
    <tr class="click row" data-dep="${esc(f.dependency_id)}">
      <td class="tw">
        <span class="twist">${ICON.chev}</span>
      </td>
      <td>
        <span class="lib">${esc(f.library_name)}</span><span class="ver">${esc(f.version)}</span>
        <div class="id">${esc(f.dependency_id)}${
          live ? ` · ${plural(live, "CVE")}${anyConfirmed ? "" : " (unconfirmed)"}` : ""
        }${worst ? ` · CVSS ${worst.toFixed(1)}` : ""}</div>
      </td>
      ${showApp ? `<td style="color:var(--ink-2)">${esc(appName(f.app_id))}</td>` : ""}
      <td><div class="tags">${riskTags(f.risk_types)}${
        f.vuln_status === "confirmed_vulnerable"
          ? '<span class="tag vs-confirmed">confirmed</span>'
          : f.vuln_status === "potential_vulnerable"
            ? '<span class="tag vs-potential">potential</span>'
            : f.vuln_status === "dismissed"
              ? '<span class="tag">dismissed</span>'
              : ""
      }</div></td>
      <td>${f.license ? esc(f.license) : '<i style="color:var(--ink-3)">unknown</i>'}</td>
      <td>${sevBadge(f.severity)}</td>
      <td class="num">
        <div class="score" style="--tone:var(--sev-${esc(f.severity)})">
          <span class="v">${score(f.risk_score)}</span>
          <span class="track"><i style="width:${score(f.risk_score)}%"></i></span>
        </div>
      </td>
    </tr>
    <tr class="detailrow" hidden><td colspan="${showApp ? 7 : 6}"></td></tr>`;
}

/* Wire expand/collapse on a tbody rendered from findingRow(). Detail HTML is
   built lazily on first open — rendering 320 CVE panels up front to show one is
   a waste of everyone's afternoon. */
export function wireRows(tbody, { byId, label }) {
  tbody.querySelectorAll("tr.row").forEach((tr) => {
    tr.addEventListener("click", () => {
      const detail = tr.nextElementSibling;
      const open = !detail.hidden;
      if (open) {
        detail.hidden = true;
        tr.classList.remove("open");
        return;
      }
      const f = byId.get(tr.dataset.dep);
      const cell = detail.firstElementChild;
      if (!cell.dataset.built) {
        cell.innerHTML = findingDetail(f, { label });
        cell.dataset.built = "1";
      }
      detail.hidden = false;
      tr.classList.add("open");
    });
  });
}

/* The stylesheet for everything above. Injected once, so the two pages that use
   findings cannot drift apart on how a CVE looks. */
export const FINDING_CSS = `
  td.tw { width: 26px; padding-right: 0; }
  .twist { display: inline-flex; color: var(--ink-3); transition: transform .14s ease; }
  .twist svg { width: 14px; height: 14px; }
  tr.open .twist { transform: rotate(90deg); color: var(--ink); }
  tr.open { background: var(--panel-2); }
  tr.open td { border-bottom-color: transparent; }
  tr.detailrow td { padding: 0; background: var(--panel-2); border-bottom: 1px solid var(--line); }

  .detail { padding: 4px 16px 18px; }
  .dcols {
    display: grid;
    grid-template-columns: minmax(220px, 1fr) minmax(260px, 1.15fr) minmax(260px, 1.3fr);
    gap: 26px;
  }
  @media (max-width: 1180px) { .dcols { grid-template-columns: 1fr; gap: 20px; } }

  .detail h4 {
    margin: 0 0 10px;
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: .09em;
    font-weight: 600;
    color: var(--ink-3);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .detail .none { margin: 0; color: var(--ink-3); font-size: 12.5px; }

  dl.kv { margin: 0; display: grid; grid-template-columns: 82px 1fr; gap: 6px 12px; font-size: 12.5px; }
  dl.kv dt { color: var(--ink-3); }
  dl.kv dd { margin: 0; word-break: break-word; }
  dl.kv dd.bad { color: var(--sev-critical); }
  dl.kv dd.warn { color: var(--sev-high); }
  dl.kv dd.ok { color: var(--sev-low); }
  dl.kv dd i { color: var(--ink-3); }

  .cve {
    padding: 10px 12px;
    border-radius: 9px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-left: 2px solid var(--tone);
    margin-bottom: 8px;
  }
  .cve:last-child { margin-bottom: 0; }
  .cve .top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .cve .cid { font-family: var(--mono); font-size: 12.5px; font-weight: 600; }
  .cve .cvss { font-variant-numeric: tabular-nums; font-size: 11.5px; font-weight: 600; color: var(--tone); }
  .cve .lines { margin-top: 7px; display: grid; gap: 4px; font-size: 12px; color: var(--ink-2); }
  .cve .lines code {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--ink);
    background: rgba(0,0,0,.32);
    padding: 1px 5px;
    border-radius: 4px;
  }
  .cve .k { color: var(--ink-3); }

  /* A false positive is a finding *about* the finding: the version matches the
     advisory range but is a backported-safe build. Strike it through and say
     why — hiding it silently would be worse, and counting it worse still. */
  .cve.fp { opacity: .72; border-left-color: var(--sev-none); }
  .cve.dismissed { opacity: .5; }
  .tag.vs-confirmed {
    color: var(--sev-critical);
    border-color: rgba(229,72,77,.4);
    background: rgba(229,72,77,.1);
  }
  .tag.vs-potential {
    color: var(--sev-medium);
    border-color: rgba(212,160,23,.4);
    background: rgba(212,160,23,.1);
  }
  .cve.fp .cid { text-decoration: line-through; text-decoration-thickness: 1px; }
  .cve .fp-note { margin-top: 7px; font-size: 11.5px; color: var(--ink-3); }
  .cve .fp-note b { color: var(--ink-2); }

  .exploit {
    display: inline-block;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: .03em;
    text-transform: uppercase;
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid var(--line-strong);
    color: var(--ink-3);
  }
  .exploit.calls { color: var(--sev-critical); border-color: rgba(229,72,77,.4); background: rgba(229,72,77,.1); }
  .exploit.imports { color: var(--sev-high); border-color: rgba(224,123,57,.4); background: rgba(224,123,57,.1); }

  .path {
    padding: 9px 11px;
    border-radius: 9px;
    background: var(--panel);
    border: 1px solid var(--line);
    margin-bottom: 7px;
  }
  .path .hops { display: flex; flex-wrap: wrap; align-items: center; gap: 4px; }
  .path .hop {
    font-family: var(--mono);
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 4px;
    background: var(--panel-3);
    color: var(--ink-2);
  }
  .path .hop.root { background: var(--accent-soft); color: #c3ccff; }
  .path .hop.term { background: rgba(229,72,77,.16); color: #f2b5b7; }
  .path .arr { color: var(--ink-3); font-size: 9px; }
  .path .via { margin-top: 6px; font-size: 11.5px; color: var(--ink-3); }
  .path .via b { color: var(--ink-2); font-family: var(--mono); font-weight: 600; }

  .narrative {
    font-size: 12.5px;
    line-height: 1.6;
    color: var(--ink-2);
    padding-left: 11px;
    border-left: 2px solid var(--line-strong);
  }

  .prio {
    display: inline-flex;
    padding: 2px 6px;
    border-radius: 5px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .04em;
    border: 1px solid var(--tone);
    color: var(--tone);
    background: color-mix(in srgb, var(--tone) 12%, transparent);
  }
  .prio-P1 { --tone: var(--sev-critical); }
  .prio-P2 { --tone: var(--sev-high); }
  .prio-P3 { --tone: var(--sev-none); }

  ol.steps { margin: 0; padding: 0; list-style: none; counter-reset: s; }
  ol.steps li {
    counter-increment: s;
    position: relative;
    padding: 0 0 9px 25px;
    font-size: 12.5px;
    line-height: 1.55;
    color: var(--ink-2);
  }
  ol.steps li:last-child { padding-bottom: 0; }
  ol.steps li::before {
    content: counter(s);
    position: absolute;
    left: 0; top: 1px;
    width: 17px; height: 17px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    font-family: var(--mono);
    font-size: 9.5px;
    color: var(--ink-3);
    border: 1px solid var(--line-strong);
  }

  .prose-src {
    margin-top: 11px;
    font-size: 11px;
    color: var(--ink-3);
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .prose-src i { width: 5px; height: 5px; border-radius: 50%; background: var(--sev-none); }
`;
