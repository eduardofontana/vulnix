# VULNIX - Web Vulnerability Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.3.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-red" alt="License">
</p>

---

## Introduction

**VULNIX** is a comprehensive web vulnerability scanner for authorized security testing, with a focus on bug bounty reconnaissance, CMS detection, and vulnerability detection.

> Warning: Use only on targets with explicit authorization. Unauthorized use is illegal.

---

## Key Features

### Vulnerability Scanning
- SQL Injection detection
- XSS (Reflected, Stored, DOM)
- Security Headers analysis
- Directory Discovery
- CSRF / IDOR / Auth checks
- HTTP Desync (Request Smuggling)
- Cloud Metadata SSRF
- WAF detection + bypass checks
- WebSocket security testing
- CVE Intelligence (NVD + KEV + EPSS)

### Advanced Vulnerabilities (v1.3.0)
- Server-Side Template Injection (SSTI)
- Local/Remote File Inclusion (LFI/RFI)
- Race Condition Detection
- XML External Entity (XXE)
- DOM-based Vulnerabilities

### Reconnaissance Tools (v1.3.0)
- DNS Lookup (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Port Scanner with service detection (100+ ports)
- SSL/TLS Certificate Analysis
- Robots.txt & Sitemap Analyzer
- Link Extractor (internal/external/API endpoints)
- GraphQL Security Scanner
- Rate Limiting Detection
- Subdomain Takeover Detection (18+ services)
- Wayback Machine Analysis
- WHOIS Lookup
- JS Secret Extraction (AWS, Google, Stripe, JWT, etc.)
- Hidden Parameter Discovery
- Content Fuzzing

### CMS Detection (v1.3.0)
- WordPress + Vulnerable Plugins
- Joomla + Components
- Drupal
- Magento
- Shopify
- Wix
- Squarespace
- Ghost
- PrestaShop
- Bitrix
- SharePoint

### Sensitive Pattern Matching
- 12+ categories (AWS keys, passwords, JWT, etc.)

### Reports
- JSON / HTML / Text / SARIF
- Consolidated Recon section
- Module Insights (evidence + remediation)

---

## Installation

Requirements:

- Python 3.11+
- pip

Installation:

```bash
pip install -r requirements.txt
```

---

## Usage

Help:

```bash
python run.py --help
```

Basic example:

```bash
python run.py https://example.com
```

### Scan Presets

```bash
# quick
python run.py https://example.com --mode quick

# standard
python run.py https://example.com --mode standard

# deep
python run.py https://example.com --mode deep -v -o reports/deep_scan
```

### Full Recon (All Tools at Once)

```bash
python run.py https://example.com --recon-all
```

This command runs ALL scanners:
- DNS Lookup
- Port Scanning (50 ports)
- SSL/TLS Analysis
- GraphQL Scanner
- Rate Limiting Detection
- Subdomain Takeover
- Wayback Analysis
- WHOIS Lookup
- CMS Detection
- JS Secret Extraction
- Parameter Discovery
- Content Fuzzing
- Sensitive Pattern Matching
- All vulnerability scans

### Individual Tools

```bash
# CMS Detection (WordPress, Joomla, Drupal, etc)
python run.py https://example.com --cms

# CVE Intelligence
python run.py https://example.com --cve-intel

# DNS + Ports + SSL
python run.py https://example.com --dns --port-scan --ssl

# GraphQL Security
python run.py https://example.com --graphql

# Subdomain Takeover
python run.py example.com --takeover

# JS Secrets Extraction
python run.py https://example.com --js-secrets

# Directory Fuzzing
python run.py https://example.com --fuzz
```

### Advanced Vulnerabilities

```bash
# Server-Side Template Injection
python run.py https://example.com --ssti

# Local File Inclusion
python run.py https://example.com --lfi

# Race Conditions
python run.py https://example.com --race

# XXE Injection
python run.py https://example.com --xxe

# DOM Vulnerabilities
python run.py https://example.com --dom

# All vulnerability tests
python run.py https://example.com --ssti --lfi --race --xxe --dom
```

### Complete Scan

```bash
python run.py https://example.com \
  --recon-all \
  --cms \
  --cve-intel \
  --ssti --lfi --race --xxe --dom \
  --format both \
  -o reports/full_scan \
  -v
```

### Update CVE Cache

```bash
python run.py --update-cve-cache
```

---

## Command Options

| Argument | Description |
|---|---|
| **Scan Profile** |
| `--mode` | Scan profile (`quick`, `standard`, `deep`) |
| `-t, --timeout` | Request timeout (seconds) |
| `-d, --depth` | Maximum crawl depth |
| `-u, --urls` | Maximum URLs to crawl |
| **Core Scanning** |
| `--no-sqli` | Disable SQLi |
| `--no-xss` | Disable XSS |
| `--no-headers` | Disable headers analysis |
| `--dirscan` | Enable directory discovery |
| `--http-desync` | Enable HTTP desync |
| `--cloud-metadata` | Enable cloud metadata SSRF |
| `--waf` | Enable WAF detection |
| `--waf-bypass` | Enable WAF bypass tests |
| `--websocket` | Enable WebSocket tests |
| `--cve-intel` | Enable CVE correlation |
| **Reconnaissance** |
| `--recon` | Enable bug bounty recon |
| `--recon-all` | Run ALL recon tools |
| `--dns` | Enable DNS lookup |
| `--dns-records` | DNS record types |
| `--port-scan` | Enable port scanning |
| `--top-ports` | Number of top ports |
| `--ssl` | Enable SSL/TLS analysis |
| `--tls-check` | Check TLS vulnerabilities |
| `--graphql` | GraphQL security scanner |
| `--rate-limit` | Rate limiting detection |
| `--proxy` | Use proxy |
| **Bug Bounty** |
| `--takeover` | Subdomain takeover check |
| `--wayback` | Wayback Machine analysis |
| `--whois` | WHOIS lookup |
| **Advanced** |
| `--js-secrets` | Extract JS secrets |
| `--params` | Discover parameters |
| `--fuzz` | Directory fuzzing |
| `--pattern` | Pattern matching |
| **CMS & Tech** |
| `--cms` | Detect CMS |
| `--tech` | Technology fingerprint |
| **Advanced Vulns** |
| `--ssti` | Server-Side Template Injection |
| `--lfi` | Local File Inclusion |
| `--race` | Race conditions |
| `--xxe` | XML External Entity |
| `--dom` | DOM vulnerabilities |
| **Output** |
| `-f, --format` | Report format |
| `-o, --output` | Output file prefix |
| `-v, --verbose` | Verbose output |

---

## Project Structure

```
vulnix/
├── cli/
│   ├── main.py           # CLI argument parser
│   └── commands.py       # Terminal display
├── config/
│   └── settings.py       # Configuration
├── core/
│   ├── scanner.py       # Main scan engine
│   ├── crawler.py      # Web crawler
│   ├── fuzzer.py      # Fuzzing engine
│   ├── request_engine.py
│   └── ...
├── modules/
│   ├── sqli.py       # SQL injection
│   ├── xss.py        # XSS detection
│   ├── headers.py    # Security headers
│   ├── recon.py      # DNS + Port scan
│   ├── ssl.py        # SSL/TLS analysis
│   ├── robots.py    # Robots.txt
│   ├── linkextractor.py
│   ├── graphql.py   # GraphQL scanner
│   ├── rate_limit.py
│   ├── proxy.py
│   ├── cms_detect.py # CMS + CVE fingerprint
│   ├── advanced_vulns.py  # SSTI, LFI, XXE, Race, DOM
│   ├── recon_more.py     # Takeover + Wayback + WHOIS
│   └── recon_advanced.py  # JS Secrets + Params + Fuzzing
├── tests/
├── requirements.txt
├── run.py
└── README.md
```

---

## Testing

```bash
python -m pytest tests -q
```

---

## CMS Detection

The scanner detects 11+ CMS platforms:

| CMS | Indicators |
|---|---|
| WordPress | wp-admin, wp-content, wp-json |
| Joomla | /administrator, components/com_ |
| Drupal | /modules, drupal.settings |
| Magento | skin/frontend, /app/ |
| Shopify | myshopify.com |
| Wix | wixsite.com |
| Squarespace | squarespace.com |
| Ghost | ghost.org |
| PrestaShop | /modules, prestashop |
| Bitrix | /bitrix/ |
| SharePoint | _layouts, MicrosoftSharePoint |

### Vulnerable Plugins Detected
- revslider, slider-revolution
- contact-form-7, wordfence
- elementor, divi-builder
- akismet, yoast

---

## Sensitivity Patterns (GF-style)

12+ categories of sensitive data:

- AWS Keys (`AKIA...`)
- Google API Keys (`AIza...`)
- Stripe Keys (`sk_live_...`)
- SendGrid, Twilio, Mailgun Keys
- Hardcoded Passwords
- JWT Tokens
- Private Keys
- Firebase Tokens
- GitHub OAuth Tokens
- Slack Tokens

---

## Ethical Use

1. Use only on authorized targets.
2. Do not perform destructive exploitation.
3. Respect request rate limits.
4. Document scope and execution.

---

## License

MIT.