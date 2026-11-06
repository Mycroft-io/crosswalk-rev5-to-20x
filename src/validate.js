import * as V from './validators.gen.js';
// Returns { ok, errors: [{ path, message }] } for one package document.
export function validate(kind, data) {
  const fn = V[kind];
  if (!fn) return { ok: false, errors: [{ path: '', message: 'No schema for this document type.' }] };
  const ok = fn(data);
  const seen = new Set();
  const errors = [];
  for (const e of fn.errors || []) {
    if (e.keyword === 'if') continue;
    const extra = e.params?.missingProperty ? '' : e.params?.allowedValues ? ` (${e.params.allowedValues.join(', ')})` : '';
    const key = `${e.instancePath}|${e.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    errors.push({ path: e.instancePath || '/', message: `${e.message}${extra}` });
  }
  return { ok, errors };
}
