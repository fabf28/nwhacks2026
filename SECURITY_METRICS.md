# VaultScan Security Metrics Roadmap

This document tracks the security vectors and metrics used for end-to-end website link analysis.

**Progress: 22/29 checks implemented (76%)**

---

## 1. Domain & Registration
- [x] **Domain Age** (Mock/Simulated)
- [x] **Registrar Info** (Mock/Simulated)
- [ ] **WHOIS Privacy** - Detection of hidden ownership.
- [ ] **Domain Expiry** - Identifying short-lived scam domains.
- [ ] **Historical Ownership** - Tracking recent domain transfers.

## 2. SSL/TLS Certificate Security ✅
- [x] **Certificate Validity** (Real-time check)
- [x] **Issuer Verification** (Real-time check)
- [x] **Expiry Date** (Real-time check)
- [x] **Certificate Chain** - Full chain inspection with depth count (real)
- [x] **TLS Version** - Support for secure protocols TLS 1.2/1.3 (real)
- [x] **Cipher Strength** - Detection of weak/moderate/strong cipher suites (real)

## 3. Network & Infrastructure ✅
- [x] **Server Geolocation** (Real via IP-API)
- [x] **ISP/Hosting Provider** (Real via IP-API)
- [x] **IP Reputation** - Blacklist checks via AbuseIPDB (requires API key)
- [x] **Reverse DNS** - Hostname/IP consistency check (real)
- [x] **Port Scanning** - Identifies suspicious open ports: FTP, SSH, RDP, MySQL, etc. (real)

## 4. Reputation & Intelligence
- [x] **Google Safe Browsing** (Real, requires API key)
- [ ] **VirusTotal** - Aggregated AV engine results.
- [ ] **PhishTank** - Community-sourced phishing database check.
- [x] **AbuseIPDB** - Checking malicious IPs (integrated in IP Reputation)

## 5. Content & Behavioral Analysis (Sandbox)
- [ ] **Redirect Chain** - Detecting multi-step "jumper" redirects.
- [ ] **JavaScript Analysis** - Monitoring for auto-downloads or obfuscated scripts.
- [ ] **Form Detection** - Flagging fake login/payment fields.
- [ ] **Keyword Analysis** - Searching for high-risk words ("Verify", "Suspended", "Login").
- [ ] **Typosquatting** - Fuzzy-matching domain against popular brands.

## 6. HTTP & Web Security
- [x] **Security Headers** - Checks 7 headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy. Includes A-F grading. (real)
- [x] **Cookie Safety** - Checks Secure, HttpOnly, SameSite flags (real)
- [ ] **Visual Mimicry** - Favicon/Logo impersonation detection.

## 7. Vulnerability Scanning ✅ NEW
- [x] **Sensitive File Exposure** - Checks 25+ paths: `.env`, `.git`, `backup.sql`, `wp-config.php`, etc. (real)
- [x] **Version Disclosure** - Extracts Server, X-Powered-By headers (real)
- [x] **Admin Panel Detection** - Scans 20+ common admin/login/API endpoints (real)
- [ ] **HTTP Method Testing** - Check for PUT/DELETE/OPTIONS (Deep Scan)
- [ ] **Open Redirect Detection** (Deep Scan)

---

## API Keys Required
| API | Purpose | Free Tier |
|-----|---------|-----------|
| Google Safe Browsing | Threat database | ✅ Free |
| AbuseIPDB | IP reputation | ✅ 1000/day |

## Frontend Features
- [x] Auto-prepend `https://` if no protocol specified
- [x] Real-time scan progress with step-by-step updates (13 steps)
- [x] PDF report download with all metrics
- [x] QR code scanner integration
- [x] **Vulnerability section** with highlighted cards for exposed files/endpoints

## Scan Steps (13 total)
1. URL Parsing
2. Google Safe Browsing
3. WHOIS Check
4. SSL/TLS Certificate
5. Server Geolocation
6. Reverse DNS
7. Port Scanning
8. IP Reputation
9. Security Headers
10. Cookie Security
11. Sensitive File Exposure
12. Version Disclosure
13. Admin Panel Detection
