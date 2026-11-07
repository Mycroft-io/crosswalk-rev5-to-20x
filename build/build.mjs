// Builds dist/index.html (standalone, open from disk) and dist/artifact.html (body-only variant).
import fs from 'node:fs';
import crypto from 'node:crypto';
import { buildSync } from 'esbuild';
const js = buildSync({ entryPoints: ['src/app.js'], bundle: true, format: 'iife', minify: true, write: false, target: 'es2020', legalComments: 'none' }).outputFiles[0].text;
const inline = o => JSON.stringify(o).replace(/</g, '\\u003c');
const ref = JSON.parse(fs.readFileSync('data/reference.json', 'utf8'));
delete ref.schemas; // validators are precompiled; the page does not need the raw schemas
const samples = Object.fromEntries(fs.readdirSync('samples').sort().map(f => [f, JSON.parse(fs.readFileSync('samples/' + f, 'utf8'))]));
const logo = 'data:image/png;base64,' + fs.readFileSync('assets/mycroft-lockup-mask.png').toString('base64');
const page = fs.readFileSync('src/page.html', 'utf8').split('/*__LOGO__*/').join(logo)
  .replace('/*__REF__*/', () => inline(ref)).replace('/*__SAMPLES__*/', () => inline(samples))
  .replace('/*__APP__*/', () => js.replace(/<\/script/gi, '<\\/script'));
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/artifact.html', page);
// Cloudflare Pages: response headers with a Content-Security-Policy that pins the inline script by hash.
const hash = 'sha256-' + crypto.createHash('sha256').update(js.replace(/<\/script/gi, '<\\/script')).digest('base64');
const csp = `default-src 'none'; script-src '${hash}'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
fs.writeFileSync('dist/_headers', fs.readFileSync('site/_headers', 'utf8').replace('{{CSP}}', csp));
fs.writeFileSync('dist/index.html', `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="description" content="Reads a FedRAMP 20x certification package and lays it against the Rev5 control baseline for agency reviewers."><link rel="icon" href="data:,"><style>body{margin:0}[hidden]{display:none!important}</style></head><body>${page}</body></html>`);
console.log('app.js', js.length, 'page', page.length);
