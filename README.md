# 🛡️ depshield

[![CI](https://github.com/YOUR_USERNAME/depshield/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/depshield/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org)
[![GitHub Achievements](https://img.shields.io/badge/GitHub-Achievements-blueviolet.svg)](https://github.com/YOUR_USERNAME)

> Dependency vulnerability scanner for `package.json` and `requirements.txt` — find known CVEs before they find you.

## ✨ Features

- 🔍 Scans `package.json` (npm) and `requirements.txt` (pip) for known CVEs
- 📦 Built-in vulnerability database covering 20+ popular packages
- 🌐 Optional live query mode using the OSV.dev API
- 📊 Severity-ranked: CRITICAL → HIGH → MEDIUM → LOW
- 🔁 Recursive — finds all manifests in a project tree
- 💾 JSON report export; non-zero exit for CI pipelines

## 🚀 Quick Start

```bash
npm install
node src/depshield.js scan .
```

## 📖 Usage

```bash
# Scan for vulnerabilities (offline database)
node src/depshield.js scan .

# Scan with live OSV.dev API queries
node src/depshield.js scan . --live

# Save report
node src/depshield.js scan . --out report.json

# List all found dependencies
node src/depshield.js list .
```

## 🏆 Achievement Scripts

```bash
bash scripts/setup.sh
bash scripts/unlock-all.sh
```
