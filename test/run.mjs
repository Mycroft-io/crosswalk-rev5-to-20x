import fs from 'node:fs';
import assert from 'node:assert/strict';
import { zipSync, strToU8, unzipSync } from 'fflate';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import * as C from '../src/core.js';
import { validate } from '../src/validate.js';

const ref = JSON.parse(fs.readFileSync('data/reference.json', 'utf8'));
const pkg = {};
for (const f of fs.readdirSync('samples')) {
  const d = JSON.parse(fs.readFileSync('samples/' + f, 'utf8'));
  const k = C.detectType(d);
  assert.ok(k, 'detect ' + f);
  assert.ok(f.includes(C.DOC_TYPES[k].schema), `detected ${k} for ${f}`);
  pkg[k] = d;
  const v = validate(k, d);
  console.log('validate', k, v.ok, v.errors.slice(0, 3));
}
assert.equal(Object.keys(pkg).length, 6);

// normalisation
for (const [a, b] of [['ac-2.1', 'AC-02 (01)'], ['AC-2(1)', 'AC-02 (01)'], ['AC-02 (01)', 'AC-02 (01)'], ['ac-02', 'AC-02'], ['SI-4 (12)', 'SI-04 (12)'], ['nope', null]]) assert.equal(C.normControl(a), b);
assert.equal(C.oscalControl('AC-02 (01)'), 'ac-2.1');
assert.equal(await C.uuid5('www.example.com'), 'b63cdfa4-3df9-568e-97ae-006c5b8fd652'); // RFC 4122 v5, URL namespace

const meta = { generated: '2026-11-06T12:00:00Z' };
for (const cls of ['b', 'c', 'd']) {
  const m = C.buildModel(ref, pkg, cls);
  assert.equal(m.controls.length, ref.baselines[cls].length);
  assert.equal(Object.values(m.counts).reduce((a, b) => a + b, 0), m.total);
  // independent recount of "none": no KSI or rule cites the control
  const cited = new Set([...Object.values(ref.ksi), ...Object.values(ref.frr)].flatMap(x => x.controls));
  const uncited = ref.baselines[cls].filter(c => !cited.has(c)).length;
  const directUncited = m.controls.filter(c => c.direct && !c.mapped).length;
  assert.equal(m.counts.none, uncited - directUncited, 'none count class ' + cls);
  for (const c of m.controls) {
    if (c.state === 'traced') assert.ok(c.reported > 0 && !c.direct);
    if (c.state === 'silent') assert.ok(c.mapped > 0 && c.reported === 0 && !c.direct);
    if (c.state === 'none') assert.ok(c.mapped === 0 && !c.direct);
  }
  console.log(cls, m.total, m.counts, 'ksi', m.completeness.ksi.reported + '/' + m.completeness.ksi.expected, 'frr', m.completeness.frr.reported + '/' + m.completeness.frr.expected, 'vulns', m.vulns.length, 'unknown', m.unknown, 'outside', m.outsideBaseline);
}
const m = C.buildModel(ref, pkg, 'c');
console.log(m.vulns.map(v => [v.id, v.status, v.rating, v.sources.join('+')]));

// a missing status must never read as Implemented
const p2 = structuredClone(pkg); delete p2.sdr.keySecurityIndicators[0].ksiImplementationStatus;
const m2 = C.buildModel(ref, p2, 'c');
const k0 = p2.sdr.keySecurityIndicators[0].ksiId;
assert.ok(m2.controls.filter(c => c.ksi.some(k => k.id === k0)).every(c => c.state === 'attention'));
// empty package: nothing claimed
const m0 = C.buildModel(ref, {}, 'c');
assert.equal(m0.counts.direct + m0.counts.traced + m0.counts.attention, 0);

// OSCAL exports against NIST's 1.1.2 schemas
const dir = process.argv[2];
const ajv = new Ajv({ allErrors: true, strict: false }); addFormats(ajv);
for (const [name, doc] of [['ssp', await C.toOscalSsp(m, meta)], ['poam', await C.toOscalPoam(m, meta)]]) {
  const schema = JSON.parse(fs.readFileSync(`${dir}/oscal_${name}_schema.json`, 'utf8'));
  delete schema.$id;
  const fn = new Ajv({ allErrors: true, strict: false }); addFormats(fn);
  const v = fn.compile(schema);
  const ok = v(doc);
  console.log('OSCAL', name, ok, ok ? '' : JSON.stringify(v.errors.slice(0, 6), null, 1));
  assert.ok(ok, 'OSCAL ' + name);
  fs.writeFileSync(`${dir}/out-${name}.json`, JSON.stringify(doc, null, 2));
}
const again = await C.toOscalSsp(m, meta);
assert.deepEqual(again, await C.toOscalSsp(m, meta), 'deterministic');

// spreadsheet
const x = C.toXlsx(C.workbookSheets(m, meta), zipSync, strToU8);
fs.writeFileSync(`${dir}/out.xlsx`, x);
assert.ok(Object.keys(unzipSync(x)).includes('xl/worksheets/sheet4.xml'));
assert.ok(C.toCsv([['a'], ['=1+1']]).includes(`"'=1+1"`));
console.log('rows', C.controlRows(m).length - 1, C.gapRows(m).length - 1, C.registerRows(m).length - 1);
console.log('ALL TESTS PASSED');
