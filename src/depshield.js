#!/usr/bin/env node
/**
 * depshield — Dependency vulnerability scanner for package.json and requirements.txt
 * Usage: node src/depshield.js <command> [path] [options]
 */

'use strict';

const fs    = require('fs');
const path  = require('path');
const https = require('https');

const BOLD   = '\x1b[1m';
const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED    = '\x1b[31m';
const CYAN   = '\x1b[36m';
const DIM    = '\x1b[2m';
const NC     = '\x1b[0m';

// ── Known vulnerable packages database (offline, illustrative) ───────────────
// Format: { name: { '<range>': { cve, severity, description, fixedIn } } }
// A real scanner would query OSV.dev, Snyk, or NVD APIs
const KNOWN_VULNS = {
  // npm packages
  'lodash': {
    '<4.17.21': { cve: 'CVE-2021-23337', severity: 'HIGH', description: 'Command injection via template', fixedIn: '4.17.21' },
    '<4.17.19': { cve: 'CVE-2020-8203',  severity: 'HIGH', description: 'Prototype pollution via zipObjectDeep', fixedIn: '4.17.19' },
  },
  'axios': {
    '<0.21.2':  { cve: 'CVE-2021-3749',  severity: 'HIGH',     description: 'Regular expression denial of service', fixedIn: '0.21.2' },
    '<1.6.0':   { cve: 'CVE-2023-45857', severity: 'MEDIUM',   description: 'XSRF token exposure', fixedIn: '1.6.0' },
  },
  'express': {
    '<4.19.2':  { cve: 'CVE-2024-29041', severity: 'MEDIUM',   description: 'Open redirect', fixedIn: '4.19.2' },
  },
  'jsonwebtoken': {
    '<9.0.0':   { cve: 'CVE-2022-23529', severity: 'HIGH',     description: 'Insecure default algorithm', fixedIn: '9.0.0' },
  },
  'node-fetch': {
    '<2.6.7':   { cve: 'CVE-2022-0235',  severity: 'HIGH',     description: 'Exposure of sensitive information', fixedIn: '2.6.7' },
  },
  'minimist': {
    '<1.2.6':   { cve: 'CVE-2021-44906', severity: 'CRITICAL', description: 'Prototype pollution', fixedIn: '1.2.6' },
  },
  'glob-parent': {
    '<5.1.2':   { cve: 'CVE-2020-28469', severity: 'HIGH',     description: 'Regular expression denial of service', fixedIn: '5.1.2' },
  },
  'path-to-regexp': {
    '<0.1.10':  { cve: 'CVE-2024-45296', severity: 'HIGH',     description: 'ReDoS via backtracking', fixedIn: '0.1.10' },
  },
  'semver': {
    '<5.7.2':   { cve: 'CVE-2022-25883', severity: 'MEDIUM',   description: 'Regular expression denial of service', fixedIn: '5.7.2' },
    '<6.3.1':   { cve: 'CVE-2022-25883', severity: 'MEDIUM',   description: 'Regular expression denial of service', fixedIn: '6.3.1' },
    '<7.5.2':   { cve: 'CVE-2022-25883', severity: 'MEDIUM',   description: 'Regular expression denial of service', fixedIn: '7.5.2' },
  },
  'tar': {
    '<6.1.9':   { cve: 'CVE-2021-37701', severity: 'HIGH',     description: 'Arbitrary file creation/overwrite', fixedIn: '6.1.9' },
  },
  'vm2': {
    '<3.9.19':  { cve: 'CVE-2023-29017', severity: 'CRITICAL', description: 'Sandbox escape', fixedIn: '3.9.19' },
  },
  // Python packages
  'pillow': {
    '<10.0.1':  { cve: 'CVE-2023-44271', severity: 'HIGH',     description: 'Uncontrolled resource consumption', fixedIn: '10.0.1' },
  },
  'requests': {
    '<2.31.0':  { cve: 'CVE-2023-32681', severity: 'MEDIUM',   description: 'Proxy header leak via redirect', fixedIn: '2.31.0' },
  },
  'cryptography': {
    '<41.0.3':  { cve: 'CVE-2023-38325', severity: 'HIGH',     description: 'SSH key handling flaw', fixedIn: '41.0.3' },
  },
  'werkzeug': {
    '<3.0.3':   { cve: 'CVE-2024-34069', severity: 'HIGH',     description: 'Remote code execution via debugger', fixedIn: '3.0.3' },
  },
  'django': {
    '<4.2.13':  { cve: 'CVE-2024-38875', severity: 'HIGH',     description: 'Denial of service via multipart form data', fixedIn: '4.2.13' },
  },
  'flask': {
    '<3.0.3':   { cve: 'CVE-2023-30861', severity: 'HIGH',     description: 'Session cookie leak', fixedIn: '3.0.3' },
  },
  'aiohttp': {
    '<3.9.4':   { cve: 'CVE-2024-23334', severity: 'HIGH',     description: 'Path traversal', fixedIn: '3.9.4' },
  },
};

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const SEV_COLOR = { CRITICAL: RED, HIGH: YELLOW, MEDIUM: CYAN, LOW: DIM };

// ── Version comparison ────────────────────────────────────────────────────────
function parseVersion(v) {
  if (!v) return [0, 0, 0];
  const clean = v.replace(/^[~^>=<\s]+/, '').split('-')[0];
  return clean.split('.').slice(0, 3).map(n => parseInt(n) || 0);
}

function versionLt(a, b) {
  const av = parseVersion(a), bv = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    if (av[i] < bv[i]) return true;
    if (av[i] > bv[i]) return false;
  }
  return false;
}

function cleanVersion(v) {
  return v ? v.replace(/^[~^>=<\s*]+/, '') : v;
}

// ── Parsers ───────────────────────────────────────────────────────────────────
function parsePackageJson(filePath) {
  try {
    const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
    return Object.entries(deps).map(([name, version]) => ({
      name, version: cleanVersion(String(version)), raw: String(version), type: 'npm',
    }));
  } catch (e) {
    console.error(`❌ Failed to parse ${filePath}: ${e.message}`); return [];
  }
}

function parseRequirementsTxt(filePath) {
  try {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    return lines
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !l.startsWith('-'))
      .map(l => {
        const [nameVer] = l.split(';'); // strip env markers
        const match = nameVer.match(/^([A-Za-z0-9\-_.]+)\s*([><=!~]+)\s*([\d.]+)/);
        if (match) return { name: match[1].toLowerCase(), version: match[3], raw: l.trim(), type: 'pip' };
        return { name: nameVer.trim().toLowerCase(), version: null, raw: l.trim(), type: 'pip' };
      })
      .filter(d => d.name);
  } catch (e) {
    console.error(`❌ Failed to parse ${filePath}: ${e.message}`); return [];
  }
}

function findManifests(targetPath) {
  const manifests = [];
  const stat = fs.statSync(targetPath);

  if (stat.isFile()) {
    const base = path.basename(targetPath);
    if (base === 'package.json') manifests.push({ file: targetPath, type: 'npm' });
    else if (base === 'requirements.txt' || base.endsWith('.txt')) manifests.push({ file: targetPath, type: 'pip' });
    return manifests;
  }

  // Walk directory
  const check = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (['.git','node_modules','dist','build','.venv','venv','__pycache__'].includes(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) check(full);
      else if (e.name === 'package.json') manifests.push({ file: full, type: 'npm' });
      else if (e.name === 'requirements.txt') manifests.push({ file: full, type: 'pip' });
    }
  };
  check(targetPath);
  return manifests;
}

// ── Vulnerability scanner ─────────────────────────────────────────────────────
function checkDependencies(deps, sourceFile) {
  const findings = [];
  for (const dep of deps) {
    const vulnMap = KNOWN_VULNS[dep.name];
    if (!vulnMap) continue;
    if (!dep.version) {
      findings.push({ ...dep, sourceFile, cve: 'UNKNOWN', severity: 'LOW', description: 'No version pinned — cannot assess vulnerabilities', fixedIn: 'Pin a version' });
      continue;
    }
    for (const [range, vuln] of Object.entries(vulnMap)) {
      const threshold = range.replace(/^</, '');
      if (versionLt(dep.version, threshold)) {
        findings.push({ ...dep, sourceFile, ...vuln });
      }
    }
  }
  return findings;
}

// ── OSV.dev API check (live, optional) ────────────────────────────────────────
function queryOSV(ecosystem, name, version) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ version, package: { name, ecosystem } });
    const req  = https.request({
      hostname: 'api.osv.dev',
      path:     '/v1/query',
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const vulns = json.vulns || [];
          resolve(vulns.map(v => ({
            id: v.id, summary: v.summary, severity: (v.database_specific && v.database_specific.severity) || 'MEDIUM',
          })));
        } catch { resolve([]); }
      });
    });
    req.on('error', () => resolve([]));
    req.setTimeout(5000, () => { req.destroy(); resolve([]); });
    req.write(body);
    req.end();
  });
}

// ── Commands ──────────────────────────────────────────────────────────────────
async function scanCommand(targetPath, opts = {}) {
  const resolved = path.resolve(targetPath || '.');
  console.log(`\n${BOLD}${CYAN}🛡️  depshield — Dependency Vulnerability Scanner${NC}`);
  console.log(`Scanning: ${resolved}\n`);

  const manifests = findManifests(resolved);
  if (manifests.length === 0) {
    console.log(`${YELLOW}⚠️  No package.json or requirements.txt found in ${resolved}${NC}`);
    return;
  }

  console.log(`Found ${manifests.length} manifest(s): ${manifests.map(m => path.basename(m.file)).join(', ')}\n`);

  let allFindings = [];
  let totalDeps   = 0;

  for (const manifest of manifests) {
    const deps = manifest.type === 'npm'
      ? parsePackageJson(manifest.file)
      : parseRequirementsTxt(manifest.file);

    totalDeps += deps.length;
    const findings = checkDependencies(deps, manifest.file);

    if (opts.live && deps.length <= 20) {
      // Optionally query OSV.dev for live data
      process.stdout.write(`  Querying OSV.dev for ${deps.length} packages... `);
      for (const dep of deps.slice(0, 10)) { // limit API calls
        if (!dep.version) continue;
        const eco = manifest.type === 'npm' ? 'npm' : 'PyPI';
        const vulns = await queryOSV(eco, dep.name, dep.version);
        for (const v of vulns) {
          if (!findings.find(f => f.name === dep.name && f.cve === v.id)) {
            findings.push({ ...dep, sourceFile: manifest.file, cve: v.id, severity: v.severity, description: v.summary, fixedIn: 'Check advisory' });
          }
        }
      }
      console.log('done');
    }

    allFindings = allFindings.concat(findings);
  }

  allFindings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  if (allFindings.length === 0) {
    console.log(`${GREEN}✅ No known vulnerabilities found in ${totalDeps} dependencies.${NC}\n`);
    console.log(`${DIM}Note: This uses a built-in database. Run with --live for OSV.dev queries.${NC}`);
    return;
  }

  const bySev = {};
  for (const f of allFindings) {
    if (!bySev[f.severity]) bySev[f.severity] = [];
    bySev[f.severity].push(f);
  }

  for (const sev of ['CRITICAL','HIGH','MEDIUM','LOW']) {
    if (!bySev[sev]) continue;
    const col = SEV_COLOR[sev];
    console.log(`${col}${BOLD}── ${sev} (${bySev[sev].length}) ${'─'.repeat(38)}${NC}`);
    for (const f of bySev[sev]) {
      console.log(`  ${col}${BOLD}[${f.cve || '?'}]${NC} ${f.name}@${f.version || '?'}  ${DIM}(${f.type})${NC}`);
      console.log(`  ${DIM}File:${NC}    ${f.sourceFile}`);
      console.log(`  ${DIM}Issue:${NC}   ${f.description}`);
      console.log(`  ${GREEN}Fix:${NC}     Upgrade to ${f.fixedIn}`);
      console.log('');
    }
  }

  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of allFindings) { if (summary[f.severity] !== undefined) summary[f.severity]++; }
  console.log('─'.repeat(50));
  console.log(`${BOLD}Scanned: ${totalDeps} deps | Vulnerable: ${allFindings.length}${NC}`);
  console.log(`  Critical: ${summary.CRITICAL}  High: ${summary.HIGH}  Medium: ${summary.MEDIUM}  Low: ${summary.LOW}`);

  if (opts.output) {
    const report = { scannedAt: new Date().toISOString(), totalDeps, totalVulnerable: allFindings.length, summary, findings: allFindings };
    fs.writeFileSync(opts.output, JSON.stringify(report, null, 2));
    console.log(`\n📄 Report saved: ${opts.output}`);
  }

  if (!opts.noExit && summary.CRITICAL > 0) process.exit(1);
}

function listCommand(targetPath) {
  const resolved = path.resolve(targetPath || '.');
  const manifests = findManifests(resolved);

  console.log(`\n${BOLD}${CYAN}🛡️  depshield — Dependency List${NC}\n`);

  for (const manifest of manifests) {
    const deps = manifest.type === 'npm'
      ? parsePackageJson(manifest.file)
      : parseRequirementsTxt(manifest.file);
    console.log(`${BOLD}${manifest.file}${NC} (${deps.length} deps)`);
    deps.forEach(d => console.log(`  ${d.name}@${d.version || '(unpinned)'}`));
    console.log('');
  }
}

// ── CLI ───────────────────────────────────────────────────────────────────────
const [,, cmd, arg1, ...rest] = process.argv;

if (!cmd || cmd === 'help') {
  console.log('depshield — Dependency Vulnerability Scanner\n');
  console.log('Commands:');
  console.log('  scan [path]              Scan for known CVEs (default: current dir)');
  console.log('  scan [path] --live       Also query OSV.dev API for live data');
  console.log('  scan [path] --out file   Save JSON report');
  console.log('  scan [path] --no-exit    Do not exit 1 on critical findings');
  console.log('  list [path]              List all found dependencies');
  console.log('\nExamples:');
  console.log('  node src/depshield.js scan .');
  console.log('  node src/depshield.js scan . --live --out report.json');
  console.log('  node src/depshield.js list .');
  process.exit(0);
}

(async () => {
  if (cmd === 'scan') {
    const outIdx = rest.indexOf('--out');
    const output = outIdx !== -1 ? rest[outIdx + 1] : null;
    await scanCommand(arg1, { output, live: rest.includes('--live'), noExit: rest.includes('--no-exit') });
  } else if (cmd === 'list') {
    listCommand(arg1);
  } else {
    console.error(`Unknown command: ${cmd}`); process.exit(1);
  }
})();
