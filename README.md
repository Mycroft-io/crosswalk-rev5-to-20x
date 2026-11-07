# Crosswalk 20x

A single web page that reads a FedRAMP certification package (the JSON files CR26 introduced) and lays it against the Rev5 control baseline, so an agency reviewer can see what the provider's package covers and what is left for the agency to decide.

It runs entirely in the browser. Package files are never uploaded, the page makes no network requests, and `dist/index.html` works when opened from disk.

**Status: prototype (0.1).** Built and maintained by [Mycroft](https://mycroft.io). Not a FedRAMP tool and not endorsed by FedRAMP.

## What it does

1. **Loads a package.** Drop in any of: Certification Package Overview, Security Decision Record, Ongoing Certification Report, Vulnerability Detail Report, Accepted Vulnerability Info, Historical Vulnerability Activity. Each file is checked against FedRAMP's published schema.
2. **Pivots the decision record to controls.** For every control in the Class B, C or D Rev5 baseline it shows the Key Security Indicators and FedRAMP rules that FedRAMP maps to it, what the provider reported for each, and FedRAMP's own agency actions for that control.
3. **Says what the package does not cover.** Every control gets one of five states:

   | State | Meaning |
   |---|---|
   | Documented | The provider has its own entry for this control. |
   | Traced | Mapped indicators or rules are reported, and every reported one is Implemented. |
   | Needs review | A mapped entry is partially implemented, not implemented, or has no status. |
   | Not reported | FedRAMP maps indicators to the control, but the package reports none of them. |
   | No mapping | FedRAMP maps nothing to the control. The agency decides. |

4. **Builds a vulnerability register** from the vulnerability reports, one row per provider tracking ID.
5. **Exports** a review workbook (.xlsx), CSVs, a readable report (.html), an OSCAL 1.1.2 SSP skeleton for the agency system, and an OSCAL 1.1.2 POA&M.

## What it is not

The control links are the "related controls" FedRAMP publishes for each indicator and rule. A link shows a reviewer where to look. It is not evidence that a control is satisfied, and the output is not a System Security Plan or a POA&M. The OSCAL SSP export is a skeleton of the *agency's* plan with the cloud service as one component; fields that describe the agency system are marked `AGENCY TO COMPLETE`.

FedRAMP's own [JSONViewer](https://github.com/FedRAMP/JSONViewer) already renders single package files and has an agency view that lists mapped rules per control. This project adds whole-package loading, schema validation, coverage states and counts, the vulnerability register and the exports.

## Build

```
git clone --depth 1 https://github.com/FedRAMP/rules vendor/rules
git clone --depth 1 https://github.com/FedRAMP/schemas vendor/schemas
git clone --depth 1 https://github.com/FedRAMP/JSONViewer vendor/JSONViewer
npm install
npm run data     # rebuild data/reference.json from FedRAMP's sources
npm run build    # dist/index.html
npm test         # needs NIST's oscal_ssp_schema.json and oscal_poam_schema.json (v1.1.2) in vendor/oscal
```

`data/reference.json` in this repository was built from FedRAMP rules version 2026.11.02.01 (`FedRAMP/rules@64fa769`), `FedRAMP/schemas@8fe79fa` and `FedRAMP/JSONViewer@128f6cc`. The files in `samples/` are FedRAMP's fictional test fixtures from JSONViewer. All of these are public domain (CC0).

## Hosting

The site is deployed with Cloudflare Pages from this repository. Settings in the Cloudflare dashboard:

| Setting | Value |
|---|---|
| Production branch | `main` |
| Build command | `npm ci && npm run build` |
| Build output directory | `dist` |
| Node version | from `.node-version` (22) |

The build writes `dist/_headers`, which Cloudflare applies to every response. It carries a Content-Security-Policy that allows only the page's own inline script (pinned by SHA-256 hash, recomputed on each build), inline styles, and `data:` images for the embedded logo. Everything else, including any network request, is refused by the browser. Do not add analytics scripts: the page's promise that it makes no network requests is part of its value to agency reviewers, and the policy would block them anyway.

## Layout

- `src/core.js` — the crosswalk and the exporters. Pure functions, no DOM.
- `src/validate.js`, `src/validators.gen.js` — FedRAMP's schemas precompiled to plain functions, so the page needs no `eval` and runs under a strict Content-Security-Policy.
- `src/app.js`, `src/page.html` — the page.
- `build/` — data, validator and page builds.
- `site/_headers` — Cloudflare Pages response headers; the build fills in the CSP hash.
- `test/run.mjs` — checks the crosswalk counts, validates both OSCAL exports against NIST's schemas, and opens the workbook.

## Known limits

- The package overview does not state a certification class, so the reviewer picks the baseline.
- "Applicable FedRAMP rules" is computed from the type, class and affected-party metadata in the rules file, without checking effective dates.
- Class D has no published 20x indicator statements yet; Class D uses the common statements only.
- No native Word export; the readable report opens in Word.
- Tested against FedRAMP's sample package only. It has not been run against a real certification package.

## Licence

Code: Apache-2.0, copyright 2026 Mycroft Technologies Inc. See `LICENSE` and `NOTICE`.

Bundled FedRAMP data (`data/reference.json`, `samples/`) is public domain (CC0), from FedRAMP's repositories.
