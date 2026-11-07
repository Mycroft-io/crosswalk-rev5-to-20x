# Changelog

## 1.0.0 (2026-11-07)

First release.

- Loads the six FedRAMP 20x package file types and validates each against FedRAMP's CR26 schemas, in the browser.
- Lays the Security Decision Record against the Rev5 Class B, C or D baseline with five coverage states per control, using FedRAMP's own KSI and rule mappings (Consolidated Rules 2026.11.02.01).
- Shows FedRAMP's agency control guidance beside each control.
- Builds a vulnerability register from the vulnerability reports.
- Exports a review workbook, CSVs, a readable report, an OSCAL 1.1.2 SSP skeleton and an OSCAL 1.1.2 POA&M.
- Deployed to GitHub Pages on every push; Cloudflare Pages headers with a hashed Content-Security-Policy included.
