"""Builds data/reference.json from FedRAMP's public-domain sources.
Usage: python3 -I build/make_data.py <rules.json> <control-titles.json> <agency-guidance.json> <schemas-dir> <out.json>
"""
import json, re, sys, glob, os
rules_p, titles_p, guid_p, schemas_d, out_p = sys.argv[1:6]
R = json.load(open(rules_p)); T = json.load(open(titles_p)); G = json.load(open(guid_p))

def norm(cid):
    m = re.match(r'^([a-z]{2})-(\d+)(?:\.(\d+))?$', cid.strip(), re.I)
    if not m: return None
    b = '%s-%02d' % (m.group(1).upper(), int(m.group(2)))
    return b + (' (%02d)' % int(m.group(3)) if m.group(3) else '')

def statements(v):
    if 'statement' in v: return {'*': v['statement']}
    return {c: x.get('statement', '') for c, x in v.get('varies_by_class', {}).items()}
def forces(v):
    if 'force' in v: return {'*': v['force']}
    return {c: x.get('force', '') for c, x in v.get('varies_by_class', {}).items() if x.get('force')}

ksi = {}
for tk, t in R['KSI'].items():
    for iid, v in t['indicators'].items():
        ksi[iid] = {'name': v['name'], 'theme': t['name'], 'st': statements(v),
                    'controls': sorted({norm(c) for c in v.get('controls', []) if norm(c)})}

frr = {}
for pk, p in R['FRR'].items():
    info = p['info']
    for bucket, subs in p['data'].items():
        for sk, reqs in subs.items():
            sub = (info.get('subsets') or {}).get(sk) or (info.get(bucket, {}).get('subsets') or {}).get(sk) or {}
            app = sub.get('applicability', {})
            for rid, v in reqs.items():
                frr[rid] = {'name': v.get('name', ''), 'set': info['name'], 'bucket': bucket, 'st': statements(v),
                            'force': forces(v), 'affects': v.get('affects') or app.get('affects', []),
                            'types': app.get('types', []), 'classes': app.get('classes', []),
                            'controls': sorted({norm(c) for c in v.get('controls', []) if norm(c)})}

bsl = R['FRR']['FRC']['data']['rev5']['CSF']['FRC-CSF-BSL']['varies_by_class']
baselines = {c: sorted(sum(v['rev5_controls_list'].values(), [])) for c, v in bsl.items()}

guid = {}
for fam, ctrls in G['controls'].items():
    for cid, c in ctrls.items():
        parts = []
        for pk, pv in (c.get('parts') or {}).items():
            if (pv.get('agency_actions') or pv.get('fedramp_guidance') or pv.get('notes')):
                parts.append([pk, pv.get('agency_actions') or '', pv.get('fedramp_guidance') or '', pv.get('notes') or ''])
        if parts: guid[cid] = parts

schemas = {}
for f in sorted(glob.glob(os.path.join(schemas_d, 'fedramp-*-schema-*.json'))):
    s = json.load(open(f)); schemas[s['$id']] = s

out = {'rulesVersion': R['info']['version'], 'rulesUpdated': R['info']['last_updated'],
       'ksi': ksi, 'frr': frr, 'baselines': baselines, 'titles': T, 'guidance': guid, 'schemas': schemas}
json.dump(out, open(out_p, 'w'), separators=(',', ':'), ensure_ascii=False)

# report
allmapped = set().union(*[set(k['controls']) for k in ksi.values()])
frrmapped = set().union(*[set(k['controls']) for k in frr.values()])
print('rules', out['rulesVersion'], 'KSIs', len(ksi), 'with controls', sum(1 for k in ksi.values() if k['controls']),
      'unique KSI controls', len(allmapped), 'refs', sum(len(k['controls']) for k in ksi.values()))
print('FRR', len(frr), 'with controls', sum(1 for k in frr.values() if k['controls']), 'unique FRR controls', len(frrmapped))
for c, b in baselines.items():
    bs = set(b)
    print(c, len(bs), 'ksi-traced', len(bs & allmapped), 'frr-only', len((bs & frrmapped) - allmapped), 'untraced', len(bs - allmapped - frrmapped),
          'agency-guidance', len(bs & set(guid)), 'titles-missing', len(bs - set(T)))
print('KSI controls outside class D baseline', len(allmapped - set(baselines['d'])), sorted(allmapped - set(baselines['d']))[:12])
print('vbc KSIs', {k: list(v['st']) for k, v in ksi.items() if '*' not in v['st']})
print('size', os.path.getsize(out_p))
