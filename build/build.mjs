// Builds dist/index.html (standalone, open from disk) and dist/artifact.html (body-only variant).
import fs from 'node:fs';
import { buildSync } from 'esbuild';
const js = buildSync({ entryPoints: ['src/app.js'], bundle: true, format: 'iife', minify: true, write: false, target: 'es2020', legalComments: 'none' }).outputFiles[0].text;
const inline = o => JSON.stringify(o).replace(/</g, '\\u003c');
const ref = JSON.parse(fs.readFileSync('data/reference.json', 'utf8'));
delete ref.schemas; // validators are precompiled; the page does not need the raw schemas
const samples = Object.fromEntries(fs.readdirSync('samples').sort().map(f => [f, JSON.parse(fs.readFileSync('samples/' + f, 'utf8'))]));
const page = fs.readFileSync('src/page.html', 'utf8')
  .replace('/*__REF__*/', () => inline(ref)).replace('/*__SAMPLES__*/', () => inline(samples))
  .replace('/*__APP__*/', () => js.replace(/<\/script/gi, '<\\/script'));
fs.mkdirSync('dist', { recursive: true });
fs.writeFileSync('dist/artifact.html', page);
fs.writeFileSync('dist/index.html', `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><style>body{margin:0}[hidden]{display:none!important}</style></head><body>${page}</body></html>`);
console.log('app.js', js.length, 'page', page.length);
