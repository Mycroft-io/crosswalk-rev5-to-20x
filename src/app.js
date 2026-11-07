import { zipSync, strToU8 } from 'fflate';
import * as C from './core.js';
import { validate } from './validate.js';

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const readJson = id => JSON.parse($(id).textContent);
const safeUrl = s => (/^https?:\/\/[^\s"'<>]+$/i.test(String(s || '')) ? String(s) : null);
const link = (href, text) => {
  const u = safeUrl(href);
  return u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(text || u)}</a>` : esc(text || href);
};
const store = {
  get(k) { try { return localStorage.getItem('cw20x.' + k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem('cw20x.' + k, v); } catch { /* optional */ } },
};

const ref = readJson('ref-data');
const samples = readJson('sample-data');
const TABS = ['controls', 'vulnerabilities', 'package', 'export'];
const GLYPH = { direct: '■', traced: '●', attention: '▲', silent: '◌', none: '–' };

const state = {
  pkg: {}, files: {}, sample: false, model: null,
  cls: ['b', 'c', 'd'].includes(store.get('cls')) ? store.get('cls') : 'c',
  tab: 'controls', q: '', family: '', states: new Set(), notes: [],
};

// ---------- loading ----------

function setDoc(kind, data, name) {
  state.pkg[kind] = data;
  state.files[kind] = { name, ...validate(kind, data) };
}
function loadSample() {
  state.pkg = {}; state.files = {}; state.notes = []; state.sample = true;
  for (const [name, data] of Object.entries(samples)) setDoc(C.detectType(data), data, name);
  refresh();
}
async function loadFiles(list) {
  const files = [...list];
  if (!files.length) return;
  const notes = []; const next = [];
  for (const f of files) {
    let data;
    try { data = JSON.parse(await f.text()); } catch { notes.push(`${f.name} is not valid JSON, so it was skipped.`); continue; }
    const kind = C.detectType(data);
    if (!kind) { notes.push(`${f.name} is not a package file this tool reads (overview, decision record, ongoing report or vulnerability reports), so it was skipped.`); continue; }
    next.push([kind, data, f.name]);
  }
  if (next.length) {
    if (state.sample) { state.pkg = {}; state.files = {}; state.sample = false; }
    for (const [k, d, n] of next) {
      if (state.files[k] && state.files[k].name !== n) notes.push(`${n} replaced ${state.files[k].name} as the ${C.DOC_TYPES[k].label}.`);
      setDoc(k, d, n);
    }
  }
  state.notes = notes;
  refresh();
  if (!Object.keys(state.pkg).length && notes.length) { $('empty-notes').hidden = false; $('empty-notes').innerHTML = notes.map(n => `<p>${esc(n)}</p>`).join(''); }
  else $('empty-notes').hidden = true;
}

// ---------- rendering ----------

function refresh() {
  state.model = C.buildModel(ref, state.pkg, state.cls);
  const has = Object.keys(state.pkg).length > 0;
  $('empty').hidden = has;
  $('loaded').hidden = !has;
  if (!has) { $('notes').hidden = true; return; }
  renderHeader(); renderCoverage(); renderTab();
}

function renderHeader() {
  const m = state.model, i = m.identity;
  $('ident').innerHTML = i.service || i.provider
    ? `<div class="ident-name">${esc(i.service || 'Unnamed service')}${i.acronym ? ` <span class="mono dim">${esc(i.acronym)}</span>` : ''}</div>
       <div class="ident-meta">${[i.provider && esc(i.provider), i.packageId && `<span class="mono">${esc(i.packageId)}</span>`, `${esc(m.type)} certification`].filter(Boolean).join(' <span class="sep">/</span> ')}</div>`
    : `<div class="ident-name">No Certification Package Overview loaded</div><div class="ident-meta">Add the overview file to identify the service. The view below assumes a 20x package.</div>`;
  $('files').innerHTML = Object.keys(C.DOC_TYPES).map(k => {
    const f = state.files[k];
    const cls = !f ? 'absent' : f.ok ? 'ok' : 'bad';
    const tip = !f ? 'Not loaded' : f.ok ? `${f.name}: matches FedRAMP's schema` : `${f.name}: ${f.errors.length} schema problem${f.errors.length === 1 ? '' : 's'}`;
    return `<li class="file ${cls}" title="${esc(tip)}"><span class="file-mark" aria-hidden="true">${!f ? '○' : f.ok ? '✓' : '!'}</span>${esc(C.DOC_TYPES[k].label)}<span class="sr"> (${esc(tip)})</span></li>`;
  }).join('');
  $('sample-note').hidden = !state.sample;
  $('notes').hidden = !state.notes.length;
  $('notes').innerHTML = state.notes.map(n => `<p>${esc(n)}</p>`).join('');
  $('cls').value = state.cls;
  const mixed = new Set(Object.values(state.pkg).map(d => d.certificationPackageOverviewUri).filter(Boolean));
  $('mixed').hidden = mixed.size < 2;
}

function renderCoverage() {
  const m = state.model;
  const ev = m.counts.direct + m.counts.traced;
  const open = m.counts.silent + m.counts.none;
  $('headline').innerHTML = `<strong>${ev}</strong> of ${m.total} baseline controls have provider evidence in this package. <strong>${m.counts.attention}</strong> need review. <strong>${open}</strong> are left to the agency.`;
  $('bar').innerHTML = C.STATE_ORDER.filter(s => m.counts[s]).map(s =>
    `<span class="seg s-${s}" style="flex:${m.counts[s]} 0 0" title="${esc(C.STATES[s].label)}: ${m.counts[s]}"></span>`).join('');
  $('legend').innerHTML = C.STATE_ORDER.map(s =>
    `<button type="button" class="chip s-${s}${state.states.has(s) ? ' on' : ''}" data-state="${s}" aria-pressed="${state.states.has(s)}" title="${esc(C.STATES[s].long)}">
      <span class="glyph" aria-hidden="true">${GLYPH[s]}</span><span class="chip-n">${m.counts[s]}</span> ${esc(C.STATES[s].label)}</button>`).join('');
}

function pill(s) {
  return `<span class="pill s-${s}"><span class="glyph" aria-hidden="true">${GLYPH[s]}</span>${esc(C.STATES[s].label)}</span>`;
}
function statusTag(status, present) {
  if (!present) return `<span class="tag t-missing">Not in this package</span>`;
  if (!status) return `<span class="tag t-warn">No status given</span>`;
  return `<span class="tag ${status === 'Implemented' ? 't-ok' : 't-warn'}">${esc(status)}</span>`;
}
const paras = (label, list) => (list.length ? `<div class="kv"><div class="kv-k">${label}</div><div class="kv-v">${list.map(t => `<p>${esc(t)}</p>`).join('')}</div></div>` : '');

function entryHtml(x) {
  const e = x.entry;
  const ev = e ? e.evidence.map(v => `<li>${v.type ? `<span class="tag">${esc(v.type)}</span> ` : ''}${v.location ? link(v.location, v.description || v.location) : esc(v.description)}${v.updated ? ` <span class="dim">updated ${esc(v.updated)}</span>` : ''}${v.text ? `<pre class="evtext">${esc(v.text.slice(0, 2000))}</pre>` : ''}</li>`).join('') : '';
  return `<article class="entry${e ? '' : ' entry-missing'}">
    <header class="entry-h"><span class="mono id">${esc(x.id)}</span><span class="entry-name">${esc(x.name)}</span>${statusTag(e?.status, !!e)}</header>
    ${x.statement ? `<p class="rule-text">${esc(x.statement)}</p>` : ''}
    ${e ? paras('Provider says', e.implementation) + paras('Provider validates by', e.validation) + paras('Assessor found', e.assessment)
      + (e.tests.length ? `<div class="kv"><div class="kv-k">Tests</div><div class="kv-v"><ul>${e.tests.map(t => `<li>${esc(t)}</li>`).join('')}</ul></div></div>` : '')
      + (ev ? `<div class="kv"><div class="kv-k">Evidence</div><div class="kv-v"><ul>${ev}</ul></div></div>` : '') : ''}
  </article>`;
}

function controlBody(c) {
  const direct = c.direct ? `<article class="entry"><header class="entry-h"><span class="mono id">${esc(c.id)}</span><span class="entry-name">Provider's own entry for this control</span>${statusTag(c.direct.status, true)}</header>
      ${paras('Provider says', c.direct.description ? [c.direct.description] : [])}
      ${c.direct.parameters.length ? `<div class="kv"><div class="kv-k">Parameters</div><div class="kv-v"><ul>${c.direct.parameters.map(p => `<li><span class="mono">${esc(p.id)}</span> = ${esc(p.value)}</li>`).join('')}</ul></div></div>` : ''}</article>` : '';
  const mapped = [...c.ksi, ...c.frr];
  const pkgSide = direct + mapped.map(entryHtml).join('') ||
    `<p class="empty">FedRAMP maps no Key Security Indicator or rule to this control, and the provider has no entry for it. Nothing in the package speaks to it.</p>`;
  const agency = c.guidance.length
    ? c.guidance.map(([part, actions, guidance, notes]) => `<div class="part">${part === '_' ? '' : `<span class="mono part-id">${esc(part)}</span>`}<div>
        ${actions ? `<p class="act">${esc(actions)}</p>` : ''}${guidance ? `<p class="dim">${esc(guidance)}</p>` : ''}${notes ? `<p class="dim">${esc(notes)}</p>` : ''}</div></div>`).join('')
    : `<p class="empty">FedRAMP's agency control guidance has no entry for this control.</p>`;
  return `<div class="cols"><section><h4>What the package says</h4>${pkgSide}</section><section><h4>What stays with the agency</h4><p class="src">From FedRAMP's agency control guidance</p>${agency}</section></div>`;
}

function visibleControls() {
  const q = state.q.trim().toLowerCase();
  return state.model.controls.filter(c =>
    (!state.family || c.family === state.family) &&
    (!state.states.size || state.states.has(c.state)) &&
    (!q || c.id.toLowerCase().includes(q) || c.title.toLowerCase().includes(q) || C.oscalControl(c.id).includes(q) ||
      c.ksi.some(k => k.id.toLowerCase().includes(q) || k.name.toLowerCase().includes(q)) || c.frr.some(k => k.id.toLowerCase().includes(q))));
}

function renderControls() {
  const m = state.model;
  const fams = [...new Set(m.controls.map(c => c.family))];
  const list = visibleControls();
  const groups = fams.map(f => [f, list.filter(c => c.family === f)]).filter(([, l]) => l.length);
  const rows = groups.map(([f, l]) => `<section class="fam"><h3><span class="mono fam-code">${f}</span>${esc(C.FAMILIES[f] || '')}<span class="fam-n">${l.length}</span></h3>
    ${l.map(c => `<details class="ctl" data-id="${esc(c.id)}"><summary><span class="mono id">${esc(c.id)}</span><span class="ctl-title">${esc(c.title)}</span>
      <span class="ctl-map">${c.mapped ? `${c.reported} of ${c.mapped} mapped reported` : ''}</span>${pill(c.state)}</summary><div class="ctl-body"></div></details>`).join('')}</section>`).join('');
  $('view').innerHTML = `<div class="toolbar">
      <label class="field grow"><span class="sr">Search controls</span><input id="q" type="search" placeholder="Search by control, title or KSI, e.g. AC-02, logging, KSI-IAM" value="${esc(state.q)}" autocomplete="off"></label>
      <label class="field"><span class="sr">Control family</span><select id="family"><option value="">All families</option>${fams.map(f => `<option value="${f}"${state.family === f ? ' selected' : ''}>${f} ${esc(C.FAMILIES[f] || '')}</option>`).join('')}</select></label>
    </div>
    <p class="count" id="count">${list.length === m.total ? `All ${m.total} controls` : `${list.length} of ${m.total} controls`}${state.states.size ? `, filtered to ${[...state.states].map(s => C.STATES[s].label.toLowerCase()).join(' and ')}` : ''}. Open a control to read both sides.</p>
    ${rows || `<p class="empty pad">No controls match. Clear the search or the coverage filter.</p>`}`;
}

const fmtDay = s => (/^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : s || '');
const flag = v => (v === true ? 'Yes' : v === false ? 'No' : '');

function renderVulns() {
  const v = state.model.vulns;
  if (!v.length) {
    $('view').innerHTML = `<p class="empty pad">No vulnerability reports are loaded. Add the Vulnerability Detail Report, Accepted Vulnerability Info or Historical Vulnerability Activity file to build the register.</p>`;
    return;
  }
  const n = s => v.filter(x => x.status === s).length;
  $('view').innerHTML = `<p class="lede">${v.length} tracked ${v.length === 1 ? 'vulnerability' : 'vulnerabilities'}: ${n('Open')} open, ${n('Accepted')} accepted by the provider, ${n('Closed')} closed${v.some(x => x.overdue) ? `, <strong>${v.filter(x => x.overdue).length} overdue</strong>` : ''}.
      Ratings are FedRAMP Potential Agency Impact N-ratings, N0 (none) to N5, as the provider reported them.</p>
    <div class="scroll"><table class="reg"><thead><tr><th>Tracking ID</th><th>Status</th><th>N</th><th class="wide">Description and impact</th><th>Detected</th><th>Internet-reachable</th><th>Likely exploitable</th><th>Next reduction</th><th>Disposition</th></tr></thead><tbody>
    ${v.map(x => `<tr><td class="mono">${esc(x.id)}</td><td><span class="tag ${x.status === 'Open' ? 't-warn' : x.status === 'Accepted' ? 't-acc' : 't-ok'}">${x.status}</span>${x.overdue ? ' <span class="tag t-bad">Overdue</span>' : ''}</td>
      <td class="num">${x.rating === null ? '' : 'N' + x.rating}</td>
      <td class="wide"><p>${esc(x.description)}</p>${x.impact ? `<p class="dim">${esc(x.impact)}</p>` : ''}${x.rationale ? `<p class="dim"><strong>Accepted because:</strong> ${esc(x.rationale)}</p>` : ''}${x.overdueWhy ? `<p class="dim"><strong>Overdue:</strong> ${esc(x.overdueWhy)}</p>` : ''}</td>
      <td class="num">${esc(fmtDay(x.detectedAt))}<div class="dim">${esc(x.detectionSource)}</div></td><td>${flag(x.internetReachable)}</td><td>${flag(x.likelyExploitable)}</td>
      <td class="num">${x.nextReductionAt ? `${esc(fmtDay(x.nextReductionAt))}${x.nextReductionTarget !== null ? ` to N${x.nextReductionTarget}` : ''}` : ''}</td><td>${esc(x.disposition)}</td></tr>`).join('')}
    </tbody></table></div>`;
}

function renderPackage() {
  const m = state.model, cpo = state.pkg.cpo, ocr = state.pkg.ocr, sp = cpo?.serviceProperties || {};
  const repo = r => (r && typeof r === 'object' ? `<li>${link(r.url, r.url)}${r.authenticationRequired ? ' <span class="tag">Sign-in required</span>' : ''}<div class="dim">${esc(r.repositoryDescription || '')}</div></li>` : '');
  const tp = cpo?.thirdPartyInformationResources || {};
  const dl = rows => `<dl class="facts">${rows.filter(r => r[1]).map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const overview = cpo ? `<section class="card"><h3>Service</h3>
      ${m.identity.description ? `<p class="prose">${esc(m.identity.description)}</p>` : ''}
      ${dl([['Service model', esc((sp.serviceType || []).join(', '))], ['Deployment', esc(sp.deploymentModel || '')], ['Assessor', cpo.assessor ? esc(`${cpo.assessor.name || ''}${cpo.assessor.assessorID ? ' (' + cpo.assessor.assessorID + ')' : ''}`) : ''],
        ['Next ongoing report', esc(sp.nextOngoingCertificationReportDate || '')],
        ['Trust center', sp.trustCenter ? `<ul class="plain">${repo(sp.trustCenter)}</ul>` : ''],
        ['Secure configuration guide', sp.secureConfigurationGuidance ? `<ul class="plain">${repo(sp.secureConfigurationGuidance)}</ul>` : ''],
        ['Certified services it depends on', (tp.certified || []).length ? `<ul class="plain">${tp.certified.map(t => `<li><span class="mono">${esc(t.fedRampCertifiedThirdPartyInformationResource)}</span><div class="dim">${esc(t.useCase)}</div></li>`).join('')}</ul>` : ''],
        ['Services it uses that are not certified', (tp.nonCertified || []).length ? `<ul class="plain">${tp.nonCertified.map(t => `<li>${esc(t.name)} <span class="dim">by ${esc(t.provider)}</span><div class="dim">${esc(t.useCase)}</div></li>`).join('')}</ul>` : '']])}
    </section>` : '';
  const files = `<section class="card"><h3>Files and schema checks</h3><p class="dim">Each file is checked in this browser against FedRAMP's published schema for its type.</p><ul class="checks">
    ${Object.keys(C.DOC_TYPES).map(k => {
      const f = state.files[k];
      if (!f) return `<li class="absent"><span class="file-mark" aria-hidden="true">○</span><div><strong>${esc(C.DOC_TYPES[k].label)}</strong><div class="dim">Not loaded</div></div></li>`;
      return `<li class="${f.ok ? 'ok' : 'bad'}"><span class="file-mark" aria-hidden="true">${f.ok ? '✓' : '!'}</span><div><strong>${esc(C.DOC_TYPES[k].label)}</strong> <span class="mono dim">${esc(f.name)}</span>
        <div class="dim">${f.ok ? 'Matches the schema' : `${f.errors.length} schema problem${f.errors.length === 1 ? '' : 's'}. The file is still shown, read as written.`}</div>
        ${f.ok ? '' : `<ul class="errs">${f.errors.slice(0, 25).map(e => `<li><span class="mono">${esc(e.path)}</span> ${esc(e.message)}</li>`).join('')}${f.errors.length > 25 ? `<li>and ${f.errors.length - 25} more</li>` : ''}</ul>`}</div></li>`;
    }).join('')}</ul></section>`;
  const comp = (label, c, name) => `<div class="comp"><div class="comp-n"><strong>${c.reported}</strong> of ${c.expected}</div><div>${label}
      ${c.missing.length ? `<details><summary>${c.missing.length} not in the decision record</summary><ul class="cols3">${c.missing.map(id => `<li><span class="mono">${esc(id)}</span> ${esc(name(id))}</li>`).join('')}</ul></details>` : ''}</div></div>`;
  const completeness = `<section class="card"><h3>What the decision record covers</h3>
    ${comp(`Key Security Indicators reported`, m.completeness.ksi, id => ref.ksi[id]?.name || '')}
    ${comp(`FedRAMP rules reported, of those FedRAMP's metadata marks as applying to ${esc(m.type)} Class ${m.cls.toUpperCase()} providers`, m.completeness.frr, id => ref.frr[id]?.name || '')}
    ${m.ctlIn.size ? `<div class="comp"><div class="comp-n"><strong>${m.ctlIn.size}</strong></div><div>Rev5 controls the provider documents directly${m.outsideBaseline.length ? `; ${m.outsideBaseline.length} outside the Class ${m.cls.toUpperCase()} baseline (${m.outsideBaseline.map(esc).join(', ')})` : ''}</div></div>` : ''}
    ${m.unknown.ksi.length + m.unknown.frr.length + m.unknown.controls.length ? `<p class="warn">IDs in the package that are not in FedRAMP rules ${esc(m.rulesVersion)}: ${[...m.unknown.ksi, ...m.unknown.frr, ...m.unknown.controls].map(i => `<span class="mono">${esc(i)}</span>`).join(', ')}. They are ignored in the control view.</p>` : ''}</section>`;
  const li = a => (Array.isArray(a) && a.length ? `<ul>${a.map(t => `<li>${esc(typeof t === 'string' ? t : JSON.stringify(t))}</li>`).join('')}</ul>` : '');
  const inc = ocr?.reportableIncidents?.incidents || [];
  const ongoing = ocr ? `<section class="card"><h3>Latest ongoing report${ocr.reportPeriod ? `, ${esc(ocr.reportPeriod.from || '')} to ${esc(ocr.reportPeriod.to || '')}` : ''}</h3>
    ${dl([['Changes made', li(ocr.certificationDataChanges)], [`Changes planned${ocr.plannedCertificationDataChanges?.planningHorizonThrough ? ' through ' + esc(ocr.plannedCertificationDataChanges.planningHorizonThrough) : ''}`, li(ocr.plannedCertificationDataChanges?.changes)],
      ['Transformative changes', li(ocr.transformativeChanges)], ['Accepted vulnerabilities', esc(typeof ocr.acceptedVulnerabilities === 'string' ? ocr.acceptedVulnerabilities : '')],
      ['Reportable incidents', inc.length ? `<ul>${inc.map(i => `<li>${esc(i.summary || '')} <span class="dim">${esc(fmtDay(i.occurredAt || ''))}</span>${li(i.incidentLessonsLearned)}</li>`).join('')}</ul>` : ''],
      ['New recommendations for customers', li(ocr.updatedRecommendations)], ['Agencies using the service', li(ocr.activeAgencies)]])}</section>` : '';
  $('view').innerHTML = `<div class="stack">${overview}${files}${completeness}${ongoing}</div>`;
}

const EXPORTS = [
  { id: 'xlsx', name: 'Review workbook', ext: 'xlsx', what: 'Four sheets: summary, control inheritance, agency determinations and the vulnerability register. The one to hand a reviewer.' },
  { id: 'gaps', name: 'Agency determinations', ext: 'csv', what: 'Only the controls the package leaves open or flags, each with FedRAMP\'s agency actions.' },
  { id: 'controls', name: 'Control inheritance', ext: 'csv', what: 'Every baseline control with the provider statements, validation, assessment and evidence that map to it.' },
  { id: 'register', name: 'Vulnerability register', ext: 'csv', what: 'One row per provider tracking ID, in the column order a POA&M tracker expects.', needs: 'vulns' },
  { id: 'ssp', name: 'OSCAL SSP skeleton', ext: 'json', what: 'OSCAL 1.1.2 system security plan for the agency system, with the service as a component and its statements under each control. Agency fields are placeholders.' },
  { id: 'poam', name: 'OSCAL POA&M', ext: 'json', what: 'OSCAL 1.1.2 plan of action and milestones built from the provider\'s vulnerability reports.', needs: 'vulns' },
  { id: 'report', name: 'Readable report', ext: 'html', what: 'A single page to read, print or open in Word: coverage summary and every control, family by family.' },
];

function renderExport() {
  const m = state.model;
  $('view').innerHTML = `<p class="lede">Each file is built in this browser from the package you loaded and the Class ${m.cls.toUpperCase()} baseline. ${esc(C.NOTICE)}</p>
    <ul class="exports">${EXPORTS.map(x => {
      const off = x.needs === 'vulns' && !m.vulns.length;
      return `<li><div><strong>${esc(x.name)}</strong> <span class="mono dim">.${x.ext}</span><p class="dim">${esc(x.what)}${off ? ' Load a vulnerability report to enable it.' : ''}</p></div>
        <button type="button" class="btn" data-export="${x.id}"${off ? ' disabled' : ''}>Save</button></li>`;
    }).join('')}</ul><p id="export-status" class="status" role="status" aria-live="polite"></p>`;
}

function reportHtml(m, generated) {
  const i = m.identity;
  const fams = [...new Set(m.controls.map(c => c.family))];
  const cell = list => list.map(t => `<p>${esc(t)}</p>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Control inheritance view: ${esc(i.service)}</title><style>
body{font:11pt/1.45 Calibri,Arial,sans-serif;color:#111;margin:2em;max-width:1100px}h1{font-size:20pt;margin:0 0 .2em}h2{font-size:14pt;margin:1.6em 0 .4em;border-bottom:1px solid #999}
table{border-collapse:collapse;width:100%;margin:.5em 0}th,td{border:1px solid #999;padding:4px 6px;vertical-align:top;text-align:left;font-size:9.5pt}th{background:#eee}
.n{border:1px solid #999;padding:.6em .8em;background:#f6f6f6}.id{font-family:Consolas,monospace;white-space:nowrap}p{margin:0 0 .4em}</style></head><body>
<h1>Control inheritance view</h1><p><strong>${esc(i.service)}</strong>, ${esc(i.provider)}. Package ${esc(i.packageId)}. ${esc(m.type)} certification, compared against the Rev5 Class ${m.cls.toUpperCase()} baseline (${m.total} controls). FedRAMP rules ${esc(m.rulesVersion)}. Generated ${esc(generated)}.</p>
<p class="n">${esc(C.NOTICE)}</p>
<table><tr>${C.STATE_ORDER.map(s => `<th>${esc(C.STATES[s].label)}</th>`).join('')}</tr><tr>${C.STATE_ORDER.map(s => `<td>${m.counts[s]}</td>`).join('')}</tr><tr>${C.STATE_ORDER.map(s => `<td>${esc(C.STATES[s].long)}</td>`).join('')}</tr></table>
${fams.map(f => `<h2>${f} ${esc(C.FAMILIES[f] || '')}</h2><table><tr><th>Control</th><th>Coverage</th><th>What the package says</th><th>What stays with the agency</th></tr>
${m.controls.filter(c => c.family === f).map(c => {
    const said = [];
    if (c.direct) said.push(`${c.id} (${c.direct.status || 'no status given'}): ${c.direct.description}`);
    for (const x of [...c.ksi, ...c.frr]) said.push(x.entry ? `${x.id} ${x.name} (${x.entry.status || 'no status given'}): ${x.entry.implementation.join(' ')}` : `${x.id} ${x.name}: not in this package`);
    return `<tr><td><span class="id">${esc(c.id)}</span><br>${esc(c.title)}</td><td>${esc(C.STATES[c.state].label)}</td><td>${cell(said) || 'Nothing maps to this control.'}</td><td>${cell(c.guidance.filter(g => g[1]).map(g => (g[0] === '_' ? '' : `(${g[0]}) `) + g[1]))}</td></tr>`;
  }).join('')}</table>`).join('')}</body></html>`;
}

async function build(id) {
  const m = state.model;
  const meta = { generated: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
  const base = (m.identity.acronym || m.identity.packageId || 'package').replace(/[^A-Za-z0-9_-]+/g, '-').slice(0, 40) + `-class-${m.cls}`;
  switch (id) {
    case 'xlsx': return [`${base}-review.xlsx`, C.toXlsx(C.workbookSheets(m, meta), zipSync, strToU8)];
    case 'gaps': return [`${base}-agency-determinations.csv`, C.toCsv(C.gapRows(m))];
    case 'controls': return [`${base}-control-inheritance.csv`, C.toCsv(C.controlRows(m))];
    case 'register': return [`${base}-vulnerability-register.csv`, C.toCsv(C.registerRows(m))];
    case 'ssp': return [`${base}-oscal-ssp-skeleton.json`, JSON.stringify(await C.toOscalSsp(m, meta), null, 2)];
    case 'poam': return [`${base}-oscal-poam.json`, JSON.stringify(await C.toOscalPoam(m, meta), null, 2)];
    case 'report': return [`${base}-control-inheritance.html`, reportHtml(m, meta.generated)];
  }
  throw new Error('Unknown export');
}

async function save(id, btn) {
  const status = $('export-status');
  const say = (t, bad) => { status.textContent = t; status.classList.toggle('bad', !!bad); };
  btn.disabled = true;
  try {
    const [filename, data] = await build(id);
    if (window.claude?.use) {
      const dl = await window.claude.use('downloads');
      if (!dl) { say('Saving files is not available in this view. Open the page in a browser to save.', true); return; }
      try { await dl.save({ filename, data }); say(`Saved ${filename}.`); }
      catch (e) {
        if (e?.code === 'declined') say('Nothing was saved.');
        else if (e?.code === 'rate_limited') say('A save prompt is already open. Answer it, then try again.', true);
        else say(`Could not save ${filename} here (${e?.code || 'unavailable'}).`, true);
      }
    } else {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([data]));
      a.download = filename; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      say(`Saved ${filename}.`);
    }
  } catch (e) { say(`Could not build that file: ${e.message}`, true); }
  finally { btn.disabled = false; }
}

function renderTab() {
  for (const b of document.querySelectorAll('[data-tab]')) {
    const on = b.dataset.tab === state.tab;
    b.classList.toggle('on', on); b.setAttribute('aria-selected', String(on));
  }
  const n = state.model.vulns.length;
  $('tab-n-vulnerabilities').textContent = n ? String(n) : '';
  ({ controls: renderControls, vulnerabilities: renderVulns, package: renderPackage, export: renderExport })[state.tab]();
}
function setTab(t, fromHash) {
  state.tab = TABS.includes(t) ? t : 'controls';
  if (!fromHash) { try { history.replaceState(null, '', '#' + state.tab); } catch { location.hash = state.tab; } }
  renderTab();
}

// ---------- events ----------

document.addEventListener('click', e => {
  const t = e.target.closest('[data-tab],[data-state],[data-export],#open,#sample,[data-open],[data-sample]');
  if (!t) return;
  if (t.dataset.tab) setTab(t.dataset.tab);
  else if (t.dataset.state) {
    const s = t.dataset.state;
    state.states.has(s) ? state.states.delete(s) : state.states.add(s);
    renderCoverage();
    if (state.tab !== 'controls') setTab('controls'); else renderControls();
  } else if (t.dataset.export) save(t.dataset.export, t);
  else if (t.id === 'open' || t.hasAttribute('data-open')) $('file').click();
  else if (t.id === 'sample' || t.hasAttribute('data-sample')) loadSample();
});
document.addEventListener('toggle', e => {
  const d = e.target;
  if (!d.classList?.contains('ctl') || !d.open) return;
  const body = d.querySelector('.ctl-body');
  if (body.childElementCount) return;
  const c = state.model.controls.find(x => x.id === d.dataset.id);
  if (c) body.innerHTML = controlBody(c);
}, true);
let timer;
document.addEventListener('input', e => {
  if (e.target.id !== 'q') return;
  state.q = e.target.value;
  clearTimeout(timer);
  timer = setTimeout(() => {
    const pos = e.target.selectionStart;
    renderControls();
    const q = $('q'); q.focus(); try { q.setSelectionRange(pos, pos); } catch { /* fine */ }
  }, 140);
});
document.addEventListener('change', e => {
  if (e.target.id === 'family') { state.family = e.target.value; renderControls(); }
  else if (e.target.id === 'cls') { state.cls = e.target.value; store.set('cls', state.cls); refresh(); }
  else if (e.target.id === 'file') { loadFiles(e.target.files); e.target.value = ''; }
});
let depth = 0;
addEventListener('dragenter', e => { e.preventDefault(); if (depth++ === 0) document.body.classList.add('dragging'); });
addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; document.body.classList.remove('dragging'); } });
addEventListener('dragover', e => e.preventDefault());
addEventListener('drop', e => { e.preventDefault(); depth = 0; document.body.classList.remove('dragging'); if (e.dataTransfer?.files?.length) loadFiles(e.dataTransfer.files); });
addEventListener('hashchange', () => { if (location.hash === '#sample') loadSample(); else setTab(location.hash.slice(1), true); });

$('rules-version').textContent = ref.rulesVersion;
state.tab = TABS.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'controls';
if (location.hash === '#sample') loadSample(); else refresh();
