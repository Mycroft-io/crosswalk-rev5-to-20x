// Crosswalk core: pure functions, no DOM. Runs in the browser and in Node.
// Everything read from a package is untrusted text; nothing here renders HTML.

export const FAMILIES = {
  AC: 'Access Control', AT: 'Awareness and Training', AU: 'Audit and Accountability',
  CA: 'Assessment, Authorization, and Monitoring', CM: 'Configuration Management',
  CP: 'Contingency Planning', IA: 'Identification and Authentication', IR: 'Incident Response',
  MA: 'Maintenance', MP: 'Media Protection', PE: 'Physical and Environmental Protection',
  PL: 'Planning', PM: 'Program Management', PS: 'Personnel Security',
  PT: 'PII Processing and Transparency', RA: 'Risk Assessment',
  SA: 'System and Services Acquisition', SC: 'System and Communications Protection',
  SI: 'System and Information Integrity', SR: 'Supply Chain Risk Management',
};

export const DOC_TYPES = {
  cpo: { label: 'Certification Package Overview', schema: 'certification-package-overview' },
  sdr: { label: 'Security Decision Record', schema: 'security-decision-record' },
  ocr: { label: 'Ongoing Certification Report', schema: 'ongoing-certification-report' },
  vdr: { label: 'Vulnerability Detail Report', schema: 'vulnerability-detail-report' },
  avi: { label: 'Accepted Vulnerability Info', schema: 'accepted-vulnerability-info' },
  hist: { label: 'Historical Vulnerability Activity', schema: 'historical-ver-activity' },
};

export const STATES = {
  direct: { label: 'Documented', long: 'The provider documents this control directly in its Security Decision Record.' },
  traced: { label: 'Traced', long: 'Mapped indicators or rules are reported in the package, and every reported one is Implemented.' },
  attention: { label: 'Needs review', long: 'A mapped indicator, rule or control entry is reported as partially implemented or not implemented.' },
  silent: { label: 'Not reported', long: 'FedRAMP maps indicators or rules to this control, but this package reports none of them.' },
  none: { label: 'No mapping', long: 'FedRAMP maps no indicator or rule to this control. The package gives no evidence; the agency decides.' },
};
export const STATE_ORDER = ['direct', 'traced', 'attention', 'silent', 'none'];

export function schemaId(kind) {
  return `https://fedramp.gov/schemas/fedramp-${DOC_TYPES[kind].schema}-schema-2026-06-24.json`;
}

// Which package document is this? Decided from top-level keys only.
export function detectType(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  if (d.serviceIdentification && d.serviceProperties) return 'cpo';
  if (Array.isArray(d.fedRampRequirements) || Array.isArray(d.keySecurityIndicators) || Array.isArray(d.securityControls)) return 'sdr';
  if (Array.isArray(d.activeVulnerabilities) && 'generatedAt' in d) return 'hist';
  if (Array.isArray(d.vulnerabilities) && d.reportPeriod) return 'vdr';
  if (Array.isArray(d.acceptedVulnerabilities) && d.reportPeriod) return 'avi';
  if (Array.isArray(d.certificationDataChanges) || d.plannedCertificationDataChanges) return 'ocr';
  return null;
}

// "ac-2.1", "AC-2(1)", "AC-02 (01)", "ac-02.01" -> "AC-02 (01)". Null if not a control ID.
export function normControl(id) {
  const m = /^\s*([a-z]{2})[-_ ]?0*(\d{1,2})\s*(?:[.(]\s*0*(\d{1,2})\s*\)?)?\s*$/i.exec(String(id ?? ''));
  if (!m) return null;
  const base = `${m[1].toUpperCase()}-${m[2].padStart(2, '0')}`;
  return m[3] ? `${base} (${m[3].padStart(2, '0')})` : base;
}
// "AC-02 (01)" -> "ac-2.1"
export function oscalControl(id) {
  const m = /^([A-Z]{2})-(\d+)(?: \((\d+)\))?$/.exec(id);
  return m ? `${m[1].toLowerCase()}-${+m[2]}${m[3] ? '.' + +m[3] : ''}` : String(id).toLowerCase();
}
export function controlTitle(id, titles) {
  const own = titles[id];
  if (!own) return '';
  const base = /^([A-Z]{2}-\d{2}) \(/.exec(id)?.[1];
  return base && titles[base] ? `${titles[base]} | ${own}` : own;
}
function sortControls(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

const arr = v => (Array.isArray(v) ? v : []);
const str = v => (typeof v === 'string' ? v : v == null ? '' : String(v));
const strs = v => arr(v).map(str).filter(s => s.trim());
const STATUS_OK = 'Implemented';

function statementFor(entry, cls) {
  if (!entry) return '';
  return entry.st['*'] ?? entry.st[cls] ?? '';
}

// FedRAMP rules a provider of this type and class is expected to address in its SDR.
export function applicableRules(ref, type, cls) {
  const bucket = type === 'Rev5' ? 'rev5' : '20x';
  const C = cls.toUpperCase();
  return Object.entries(ref.frr).filter(([, r]) =>
    (r.bucket === 'all' || r.bucket === bucket) &&
    r.affects.includes('Providers') &&
    (!r.types.length || r.types.includes(type)) &&
    (!r.classes.length || r.classes.includes(C)) &&
    (r.st['*'] !== undefined || r.st[cls] !== undefined)
  ).map(([id]) => id);
}

// The whole derived view. pkg: { cpo, sdr, ocr, vdr, avi, hist } (any may be missing).
export function buildModel(ref, pkg, cls) {
  const sdr = pkg.sdr || {};
  const cpo = pkg.cpo || {};
  const type = cpo.serviceIdentification?.certificationType === 'Rev5' ? 'Rev5' : '20x';

  const ksiIn = new Map(); const frrIn = new Map(); const ctlIn = new Map();
  const unknown = { ksi: [], frr: [], controls: [] };
  for (const k of arr(sdr.keySecurityIndicators)) {
    const id = str(k?.ksiId).trim().toUpperCase();
    if (!id) continue;
    if (!ref.ksi[id]) unknown.ksi.push(id);
    ksiIn.set(id, {
      id, status: str(k.ksiImplementationStatus), implementation: strs(k.ksiImplementation),
      validation: strs(k.ksiValidation), assessment: strs(k.ksiAssessment), tests: strs(k.ksiTests),
      evidence: arr(k.ksiEvidence).filter(e => e && typeof e === 'object').map(e => ({
        type: str(e.evidenceType), description: str(e.evidenceDescription), location: str(e.evidenceLocation),
        text: str(e.evidenceText), updated: str(e.lastUpdated),
      })),
    });
  }
  for (const r of arr(sdr.fedRampRequirements)) {
    const id = str(r?.frrID).trim().toUpperCase();
    if (!id) continue;
    if (!ref.frr[id]) unknown.frr.push(id);
    frrIn.set(id, {
      id, status: str(r.frrImplementationStatus), implementation: strs(r.frrImplementation),
      validation: strs(r.frrValidation), assessment: strs(r.frrAssessment), tests: [], evidence: [],
    });
  }
  for (const c of arr(sdr.securityControls)) {
    const id = normControl(c?.controlId);
    if (!id) { if (c?.controlId) unknown.controls.push(str(c.controlId)); continue; }
    ctlIn.set(id, {
      id, status: str(c.controlImplementationStatus), description: str(c.controlImplementationDescription),
      parameters: arr(c.parameterValues).map(p => ({ id: str(p?.parameterId), value: str(p?.parameterValue) })),
    });
  }

  // control -> mapped indicator / rule IDs, from FedRAMP's own mapping
  const byControl = new Map();
  const link = (kind, id, controls) => {
    for (const c of controls) {
      if (!byControl.has(c)) byControl.set(c, { ksi: [], frr: [] });
      byControl.get(c)[kind].push(id);
    }
  };
  for (const [id, k] of Object.entries(ref.ksi)) link('ksi', id, k.controls);
  for (const [id, r] of Object.entries(ref.frr)) link('frr', id, r.controls);

  const baseline = ref.baselines[cls] || [];
  const inBaseline = new Set(baseline);
  const counts = Object.fromEntries(STATE_ORDER.map(s => [s, 0]));
  const controls = baseline.map(id => {
    const map = byControl.get(id) || { ksi: [], frr: [] };
    const ksi = map.ksi.map(k => ({ id: k, name: ref.ksi[k].name, theme: ref.ksi[k].theme, statement: statementFor(ref.ksi[k], cls), entry: ksiIn.get(k) || null }));
    const frr = map.frr.map(r => ({ id: r, name: ref.frr[r].name, set: ref.frr[r].set, statement: statementFor(ref.frr[r], cls), entry: frrIn.get(r) || null }));
    const direct = ctlIn.get(id) || null;
    const reported = [...ksi, ...frr].filter(x => x.entry);
    const mapped = ksi.length + frr.length;
    // A missing status is not treated as Implemented.
    const weak = reported.some(x => x.entry.status !== STATUS_OK) || (direct && direct.status !== STATUS_OK);
    let state;
    if (weak) state = 'attention';
    else if (direct) state = 'direct';
    else if (reported.length) state = 'traced';
    else if (mapped) state = 'silent';
    else state = 'none';
    counts[state]++;
    return {
      id, family: id.slice(0, 2), title: controlTitle(id, ref.titles), state, ksi, frr, direct,
      mapped, reported: reported.length, guidance: ref.guidance[id] || [],
    };
  });

  const expectedKsi = Object.keys(ref.ksi).filter(k => statementFor(ref.ksi[k], cls) || cls === 'd');
  const expectedFrr = applicableRules(ref, type, cls);
  const completeness = {
    ksi: { expected: expectedKsi.length, reported: expectedKsi.filter(k => ksiIn.has(k)).length, missing: expectedKsi.filter(k => !ksiIn.has(k)) },
    frr: { expected: expectedFrr.length, reported: expectedFrr.filter(r => frrIn.has(r)).length, missing: expectedFrr.filter(r => !frrIn.has(r)) },
  };
  const outside = [...ctlIn.keys()].filter(c => !inBaseline.has(c)).sort(sortControls);

  return {
    cls, type, controls, counts, total: baseline.length, completeness, unknown, outsideBaseline: outside,
    vulns: buildRegister(pkg), identity: identity(cpo), rulesVersion: ref.rulesVersion,
    ksiIn, frrIn, ctlIn,
  };
}

export function identity(cpo) {
  const s = cpo?.serviceIdentification || {};
  return {
    packageId: str(s.fedRampPackageId), provider: str(s.providerName), service: str(s.serviceName),
    acronym: str(s.serviceAcronym), type: str(s.certificationType), description: str(s.serviceDescription),
  };
}

const CLOSED = new Set(['Remediated', 'False Positive', 'Fully Mitigated']);

// One row per provider tracking ID across the vulnerability reports. Later sources win:
// the detail report, then accepted-vulnerability info, then the historical snapshot.
export function buildRegister(pkg) {
  const rows = new Map();
  const put = (v, source, accepted, rationale) => {
    if (!v || typeof v !== 'object') return;
    const id = str(v.providerTrackingId).trim();
    if (!id) return;
    const prev = rows.get(id);
    const disposition = str(v.finalDisposition);
    rows.set(id, {
      id, description: str(v.vulnerabilityDescription), impact: str(v.potentialAgencyImpact),
      detectedAt: str(v.detection?.detectedAt), detectionSource: str(v.detection?.detectionSource),
      evaluatedAt: str(v.evaluationCompletedAt),
      rating: Number.isInteger(v.currentRating) ? v.currentRating : null,
      internetReachable: typeof v.isInternetReachable === 'boolean' ? v.isInternetReachable : null,
      likelyExploitable: typeof v.isLikelyExploitable === 'boolean' ? v.isLikelyExploitable : null,
      nextReductionAt: str(v.projectedNextReduction?.estimatedAt),
      nextReductionTarget: Number.isInteger(v.projectedNextReduction?.targetRating) ? v.projectedNextReduction.targetRating : null,
      overdue: v.overdueStatus?.isOverdue === true, overdueWhy: str(v.overdueStatus?.explanation),
      supplementary: str(v.supplementaryRiskInformation), disposition,
      reductions: arr(v.painReductionEvents).length,
      accepted: accepted || prev?.accepted || false,
      rationale: rationale || prev?.rationale || '',
      status: (accepted || prev?.accepted) ? 'Accepted' : CLOSED.has(disposition) ? 'Closed' : 'Open',
      sources: [...new Set([...(prev?.sources || []), source])],
    });
  };
  for (const v of arr(pkg.vdr?.vulnerabilities)) put(v, DOC_TYPES.vdr.label, false, '');
  for (const a of arr(pkg.avi?.acceptedVulnerabilities)) put(a?.vulnerabilityDetail, DOC_TYPES.avi.label, true, str(a?.acceptanceRationale));
  for (const v of arr(pkg.hist?.activeVulnerabilities)) put(v, DOC_TYPES.hist.label, false, '');
  for (const a of arr(pkg.hist?.acceptedVulnerabilities)) put(a?.vulnerabilityDetail, DOC_TYPES.hist.label, true, str(a?.acceptanceRationale));
  const rank = { Open: 0, Accepted: 1, Closed: 2 };
  return [...rows.values()].sort((a, b) => rank[a.status] - rank[b.status] || (b.rating ?? -1) - (a.rating ?? -1) || a.id.localeCompare(b.id));
}

// ---------- tabular exports ----------

const day = s => (/^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : s);
const yn = v => (v === true ? 'Yes' : v === false ? 'No' : '');
const join = a => a.join('\n\n');

export function controlRows(model) {
  const head = ['Control', 'Title', 'Family', 'Coverage', 'Mapped KSIs', 'Reported KSIs', 'Mapped FedRAMP rules', 'Reported FedRAMP rules',
    'Provider control status', 'Provider statements', 'Provider validation', 'Independent assessment', 'Evidence', 'Agency actions (FedRAMP guidance)'];
  const rows = model.controls.map(c => {
    const rep = [...c.ksi, ...c.frr].filter(x => x.entry);
    const stmts = [];
    if (c.direct?.description) stmts.push(`[${c.id}] ${c.direct.description}`);
    for (const x of rep) for (const s of x.entry.implementation) stmts.push(`[${x.id}${x.entry.status ? ' · ' + x.entry.status : ''}] ${s}`);
    const val = rep.flatMap(x => x.entry.validation.map(s => `[${x.id}] ${s}`));
    const asm = rep.flatMap(x => x.entry.assessment.map(s => `[${x.id}] ${s}`));
    const ev = rep.flatMap(x => x.entry.evidence.map(e => `[${x.id}] ${[e.type, e.description, e.location, e.updated && 'updated ' + e.updated].filter(Boolean).join(' · ')}`));
    const agency = c.guidance.filter(g => g[1]).map(g => (g[0] === '_' ? '' : `(${g[0]}) `) + g[1]);
    return [c.id, c.title, FAMILIES[c.family] || c.family, STATES[c.state].label,
      c.ksi.map(k => k.id).join(', '), c.ksi.filter(k => k.entry).map(k => k.id).join(', '),
      c.frr.map(k => k.id).join(', '), c.frr.filter(k => k.entry).map(k => k.id).join(', '),
      c.direct?.status || '', join(stmts), join(val), join(asm), ev.join('\n'), agency.join('\n')];
  });
  return [head, ...rows];
}

export function registerRows(model) {
  const head = ['Provider tracking ID', 'Status', 'Description', 'Potential agency impact', 'N-rating (0-5)', 'Detected', 'Detection source',
    'Evaluation completed', 'Internet-reachable', 'Likely exploitable', 'Next reduction date', 'Next reduction target N-rating', 'Overdue',
    'Overdue explanation', 'Final disposition', 'Acceptance rationale', 'Supplementary risk information', 'Reported in'];
  return [head, ...model.vulns.map(v => [v.id, v.status, v.description, v.impact, v.rating ?? '', day(v.detectedAt), v.detectionSource,
    day(v.evaluatedAt), yn(v.internetReachable), yn(v.likelyExploitable), day(v.nextReductionAt), v.nextReductionTarget ?? '', v.overdue ? 'Yes' : 'No',
    v.overdueWhy, v.disposition, v.rationale, v.supplementary, v.sources.join('; ')])];
}

export function gapRows(model) {
  const head = ['Control', 'Title', 'Coverage', 'Why', 'Mapped indicators and rules not reported', 'Agency actions (FedRAMP guidance)'];
  const rows = model.controls.filter(c => c.state !== 'direct' && c.state !== 'traced').map(c => {
    const missing = [...c.ksi, ...c.frr].filter(x => !x.entry).map(x => x.id);
    const weak = [...c.ksi, ...c.frr].filter(x => x.entry && x.entry.status !== STATUS_OK).map(x => `${x.id}: ${x.entry.status || 'no status given'}`);
    if (c.direct && c.direct.status !== STATUS_OK) weak.push(`${c.id}: ${c.direct.status || 'no status given'}`);
    const why = c.state === 'attention' ? weak.join('; ') : STATES[c.state].long;
    return [c.id, c.title, STATES[c.state].label, why, missing.join(', '), c.guidance.filter(g => g[1]).map(g => (g[0] === '_' ? '' : `(${g[0]}) `) + g[1]).join('\n')];
  });
  return [head, ...rows];
}

// Cells starting with = + - @ are prefixed so a spreadsheet never runs package text as a formula.
const safeCell = v => {
  const s = str(v);
  return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
};
export function toCsv(rows) {
  return '﻿' + rows.map(r => r.map(v => `"${safeCell(v).replace(/"/g, '""')}"`).join(',')).join('\r\n') + '\r\n';
}

const xml = s => str(s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const colName = i => { let s = ''; for (i++; i > 0; i = Math.floor((i - 1) / 26)) s = String.fromCharCode(65 + ((i - 1) % 26)) + s; return s; };

// Minimal .xlsx: inline strings, bold frozen header row. sheets: [{ name, rows, widths? }]. zip: fflate.zipSync, enc: strToU8.
export function toXlsx(sheets, zip, enc) {
  const files = {};
  files['[Content_Types].xml'] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${sheets.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')}</Types>`;
  files['_rels/.rels'] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  files['xl/workbook.xml'] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((s, i) => `<sheet name="${xml(s.name.slice(0, 31))}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets></workbook>`;
  files['xl/_rels/workbook.xml.rels'] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('')}<Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
  files['xl/styles.xml'] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs></styleSheet>`;
  sheets.forEach((s, i) => {
    const n = Math.max(1, ...s.rows.map(r => r.length));
    const cols = Array.from({ length: n }, (_, c) => `<col min="${c + 1}" max="${c + 1}" width="${s.widths?.[c] ?? 24}" customWidth="1"/>`).join('');
    const body = s.rows.map((r, ri) => `<row r="${ri + 1}">${r.map((v, ci) => {
      const ref = colName(ci) + (ri + 1);
      if (typeof v === 'number' && Number.isFinite(v)) return `<c r="${ref}" s="${ri ? 2 : 1}"><v>${v}</v></c>`;
      const t = str(v).slice(0, 32000);
      return t ? `<c r="${ref}" s="${ri ? 2 : 1}" t="inlineStr"><is><t xml:space="preserve">${xml(t)}</t></is></c>` : '';
    }).join('')}</row>`).join('');
    files[`xl/worksheets/sheet${i + 1}.xml`] = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>${cols}</cols><sheetData>${body}</sheetData></worksheet>`;
  });
  return zip(Object.fromEntries(Object.entries(files).map(([k, v]) => [k, enc(v)])));
}

export function workbookSheets(model, meta) {
  const i = model.identity;
  const summary = [['Field', 'Value'],
    ['Provider', i.provider], ['Service', i.service], ['FedRAMP package ID', i.packageId], ['Certification type', model.type],
    ['Baseline compared against', `Rev5 Class ${model.cls.toUpperCase()} (FRC-CSF-BSL), ${model.total} controls`],
    ['FedRAMP rules version', model.rulesVersion], ['Generated', meta.generated],
    ...STATE_ORDER.map(s => [`${STATES[s].label}`, model.counts[s]]),
    ['KSIs reported / expected', `${model.completeness.ksi.reported} / ${model.completeness.ksi.expected}`],
    ['FedRAMP rules reported / applicable', `${model.completeness.frr.reported} / ${model.completeness.frr.expected}`],
    ['How to read this', NOTICE]];
  return [
    { name: 'Summary', rows: summary, widths: [38, 90] },
    { name: 'Control inheritance', rows: controlRows(model), widths: [12, 40, 26, 14, 28, 28, 28, 28, 18, 70, 50, 50, 50, 60] },
    { name: 'Agency determinations', rows: gapRows(model), widths: [12, 40, 14, 50, 40, 70] },
    { name: 'Vulnerability register', rows: registerRows(model), widths: [22, 10, 60, 50, 10, 12, 30, 12, 10, 10, 12, 10, 8, 30, 16, 50, 40, 30] },
  ];
}

export const NOTICE = 'This is a derived reading aid for agency reviewers, not a FedRAMP artifact and not a System Security Plan or POA&M. ' +
  'Control links come from the "related controls" FedRAMP publishes for each Key Security Indicator and rule. A link shows where to look; it does not show a control is satisfied. ' +
  'The certification package remains the source of record.';

// ---------- OSCAL exports ----------

async function sha1(bytes) {
  const c = globalThis.crypto;
  return new Uint8Array(await c.subtle.digest('SHA-1', bytes));
}
const NS = '6ba7b811-9dad-11d1-80b4-00c04fd430c8'; // RFC 4122 URL namespace
// Deterministic RFC 4122 v5 UUIDs, so re-exporting the same package gives the same IDs.
export async function uuid5(name) {
  const ns = Uint8Array.from(NS.replace(/-/g, '').match(/../g).map(h => parseInt(h, 16)));
  const nm = new TextEncoder().encode(name);
  const buf = new Uint8Array(ns.length + nm.length); buf.set(ns); buf.set(nm, ns.length);
  const h = (await sha1(buf)).slice(0, 16);
  h[6] = (h[6] & 0x0f) | 0x50; h[8] = (h[8] & 0x3f) | 0x80;
  const x = [...h].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

const PROP_NS = 'urn:crosswalk20x:props';
const TODO = 'AGENCY TO COMPLETE';
const OSCAL_STATUS = { 'Implemented': 'implemented', 'Partially Implemented': 'partial', 'Not Implemented': 'planned' };
const isoNow = meta => meta.generated;
const dt = s => (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s) ? s : null);
const httpUrl = s => (/^https?:\/\/[^\s]+$/i.test(s) ? s : null);

// An OSCAL SSP skeleton for the AGENCY system that uses the cloud service. The service is one
// component; each baseline control carries what the package says about it. Agency fields are
// left as explicit placeholders.
export async function toOscalSsp(model, meta) {
  const i = model.identity;
  const seed = `crosswalk20x:${i.packageId || i.service}:${model.cls}`;
  const u = n => uuid5(`${seed}:${n}`);
  const [docId, csoId, thisId, partyId, profId, userId] = await Promise.all(['ssp', 'cso', 'this', 'party', 'profile', 'user'].map(u));
  const reqs = [];
  for (const c of model.controls) {
    const reported = [...c.ksi, ...c.frr].filter(x => x.entry);
    const req = {
      uuid: await u(`req:${c.id}`), 'control-id': oscalControl(c.id),
      props: [{ name: 'coverage', ns: PROP_NS, value: c.state }],
    };
    for (const x of c.ksi) req.props.push({ name: 'mapped-ksi', ns: PROP_NS, value: x.id, class: x.entry ? 'reported' : 'not-reported' });
    for (const x of c.frr) req.props.push({ name: 'mapped-rule', ns: PROP_NS, value: x.id, class: x.entry ? 'reported' : 'not-reported' });
    if (c.direct || reported.length) {
      const parts = [];
      if (c.direct?.description) parts.push(`${c.id} (provider control entry${c.direct.status ? ', ' + c.direct.status : ''}): ${c.direct.description}`);
      for (const x of reported) parts.push(`${x.id} ${x.name}${x.entry.status ? ' (' + x.entry.status + ')' : ''}: ${x.entry.implementation.join(' ') || 'No implementation statement given.'}`);
      const statuses = [c.direct?.status, ...reported.map(x => x.entry.status)].filter(s => s !== undefined && s !== null);
      const worst = statuses.includes('Not Implemented') ? 'planned' : statuses.every(s => s === STATUS_OK) ? 'implemented' : 'partial';
      const links = [];
      for (const x of reported) for (const e of x.entry.evidence) { const h = httpUrl(e.location); if (h) links.push({ href: h, rel: 'evidence', text: `${x.id}: ${e.description || e.type || 'evidence'}`.slice(0, 300) }); }
      const by = {
        'component-uuid': csoId, uuid: await u(`by:${c.id}`),
        description: parts.join('\n\n'),
        'implementation-status': { state: c.direct && !reported.length ? (OSCAL_STATUS[c.direct.status] || 'partial') : worst,
          remarks: 'Status as reported by the provider for the entries listed. It is not a statement that the control is satisfied for the agency system.' },
        inherited: [{ uuid: await u(`inh:${c.id}`), description: `Provider measures reported in the FedRAMP certification package for ${i.service || 'the cloud service'}. Related-control mapping per FedRAMP Consolidated Rules ${model.rulesVersion}.` }],
      };
      if (c.direct?.parameters?.length) by['set-parameters'] = c.direct.parameters.filter(p => /^\S+$/.test(p.id) && p.value).map(p => ({ 'param-id': p.id, values: [p.value] }));
      if (by['set-parameters'] && !by['set-parameters'].length) delete by['set-parameters'];
      if (links.length) by.links = links;
      req['by-components'] = [by];
    }
    const agency = c.guidance.filter(g => g[1]).map(g => (g[0] === '_' ? '' : `(${g[0]}) `) + g[1]);
    req.remarks = [
      c.state === 'none' || c.state === 'silent' ? `${STATES[c.state].long} Agency determination required.` : '',
      agency.length ? `Agency actions per FedRAMP agency control guidance: ${agency.join(' ')}` : '',
    ].filter(Boolean).join('\n\n') || undefined;
    if (!req.remarks) delete req.remarks;
    reqs.push(req);
  }
  return { 'system-security-plan': {
    uuid: docId,
    metadata: {
      title: `Agency SSP skeleton: use of ${i.service || 'cloud service'} (${i.provider || 'provider'})`,
      'last-modified': isoNow(meta), version: '0.1-draft', 'oscal-version': '1.1.2',
      props: [{ name: 'marking', value: 'draft' }],
      roles: [{ id: 'provider', title: 'Cloud Service Provider' }],
      parties: [{ uuid: partyId, type: 'organization', name: i.provider || 'Cloud service provider' }],
      'responsible-parties': [{ 'role-id': 'provider', 'party-uuids': [partyId] }],
      remarks: `${NOTICE} Generated ${meta.generated} from FedRAMP package ${i.packageId || '(no package ID)'} against the Rev5 Class ${model.cls.toUpperCase()} baseline. Fields marked "${TODO}" describe the agency system and are not in the package.`,
    },
    'import-profile': { href: `#${profId}`, remarks: 'FedRAMP publishes this baseline as a control list (FRC-CSF-BSL), not as an OSCAL profile.' },
    'system-characteristics': {
      'system-ids': [{ id: TODO }], 'system-name': TODO, description: TODO,
      'system-information': { 'information-types': [{ title: TODO, description: TODO }] },
      status: { state: 'other', remarks: TODO },
      'authorization-boundary': { description: TODO },
    },
    'system-implementation': {
      users: [{ uuid: userId, title: TODO }],
      components: [
        { uuid: thisId, type: 'this-system', title: TODO, description: 'The agency information system that uses the cloud service.', status: { state: 'other', remarks: TODO } },
        { uuid: csoId, type: 'system', title: i.service || 'Cloud service offering', description: (i.description || 'FedRAMP certified cloud service offering.').slice(0, 4000),
          props: [
            ...(i.packageId ? [{ name: 'fedramp-package-id', ns: PROP_NS, value: i.packageId }] : []),
            { name: 'certification-type', ns: PROP_NS, value: model.type },
            { name: 'implementation-point', value: 'external' },
          ],
          status: { state: 'operational' }, 'responsible-roles': [{ 'role-id': 'provider', 'party-uuids': [partyId] }] },
      ],
    },
    'control-implementation': {
      description: `Controls in the FedRAMP Rev5 Class ${model.cls.toUpperCase()} baseline, each with what the provider's certification package reports for it. Coverage: ${STATE_ORDER.map(s => `${model.counts[s]} ${STATES[s].label.toLowerCase()}`).join(', ')}.`,
      'implemented-requirements': reqs,
    },
    'back-matter': { resources: [{ uuid: profId, title: `FedRAMP Rev5 Class ${model.cls.toUpperCase()} baseline (FRC-CSF-BSL)`,
      description: `Control list from FedRAMP Consolidated Rules for 2026, version ${model.rulesVersion}.`,
      rlinks: [{ href: 'https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json' }] }] },
  } };
}

const RISK_STATUS = { Open: 'open', Accepted: 'deviation-approved', Closed: 'closed' };

export async function toOscalPoam(model, meta) {
  const i = model.identity;
  const seed = `crosswalk20x:${i.packageId || i.service}:poam`;
  const u = n => uuid5(`${seed}:${n}`);
  const observations = [], risks = [], items = [];
  for (const v of model.vulns) {
    const [oid, rid, pid] = await Promise.all([u(`obs:${v.id}`), u(`risk:${v.id}`), u(`item:${v.id}`)]);
    const title = `${v.id}: ${(v.description || 'Vulnerability').replace(/\s+/g, ' ').slice(0, 120)}`;
    const props = [{ name: 'provider-tracking-id', ns: PROP_NS, value: v.id }];
    if (v.rating !== null) props.push({ name: 'potential-agency-impact-n-rating', ns: PROP_NS, value: String(v.rating) });
    if (v.internetReachable !== null) props.push({ name: 'internet-reachable', ns: PROP_NS, value: String(v.internetReachable) });
    if (v.likelyExploitable !== null) props.push({ name: 'likely-exploitable', ns: PROP_NS, value: String(v.likelyExploitable) });
    if (v.overdue) props.push({ name: 'overdue', ns: PROP_NS, value: 'true' });
    if (v.disposition) props.push({ name: 'final-disposition', ns: PROP_NS, value: v.disposition.toLowerCase().replace(/\s+/g, '-') });
    observations.push({ uuid: oid, title, description: v.description || 'No description given.', methods: ['TEST'], types: ['finding'],
      collected: dt(v.detectedAt) || isoNow(meta),
      remarks: [v.detectionSource && `Detection source: ${v.detectionSource}.`, !dt(v.detectedAt) && 'Detection time missing or malformed in the package; export time used.'].filter(Boolean).join(' ') || undefined });
    const risk = { uuid: rid, title, description: v.description || 'No description given.',
      statement: v.impact || 'No potential agency impact statement given.', props, status: RISK_STATUS[v.status],
      'related-observations': [{ 'observation-uuid': oid }] };
    const dl = dt(v.nextReductionAt); if (dl) risk.deadline = dl;
    const rem = [v.rationale && `Acceptance rationale: ${v.rationale}`, v.supplementary, v.overdueWhy && `Overdue: ${v.overdueWhy}`].filter(Boolean).join('\n\n');
    risks.push(risk);
    const item = { uuid: pid, title, description: v.description || 'No description given.', props: [{ name: 'status', ns: PROP_NS, value: v.status.toLowerCase() }],
      'related-observations': [{ 'observation-uuid': oid }], 'related-risks': [{ 'risk-uuid': rid }] };
    if (rem) item.remarks = rem;
    items.push(item);
    if (!observations.at(-1).remarks) delete observations.at(-1).remarks;
  }
  const doc = { uuid: await u('doc'),
    metadata: { title: `Provider vulnerability register: ${i.service || 'cloud service'} (${i.provider || 'provider'})`,
      'last-modified': isoNow(meta), version: '0.1-draft', 'oscal-version': '1.1.2',
      remarks: `${NOTICE} Built from the provider's Vulnerability Evaluation and Reporting files. Ratings are FedRAMP Potential Agency Impact N-ratings (N0 to N5) as reported; they are not converted to Low/Moderate/High.` },
    'system-id': { id: i.packageId || TODO, 'identifier-type': 'https://fedramp.gov' },
    'poam-items': items };
  if (observations.length) { doc.observations = observations; doc.risks = risks; }
  return { 'plan-of-action-and-milestones': doc };
}
