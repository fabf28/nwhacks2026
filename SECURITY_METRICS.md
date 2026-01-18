# VaultScan Security Metrics Roadmap

This document tracks the security vectors and metrics used for end-to-end website link analysis.

## 1. Domain & Registration
- [x] **Domain Age** (Mock/Simulated)
- [x] **Registrar Info** (Mock/Simulated)
- [ ] **WHOIS Privacy** - Detection of hidden ownership.
- [ ] **Domain Expiry** - Identifying short-lived scam domains.
- [ ] **Historical Ownership** - Tracking recent domain transfers.

## 2. SSL/TLS Certificate Security
- [x] **Certificate Validity** (Real-time check)
- [x] **Issuer Verification** (Real-time check)
- [x] **Expiry Date** (Real-time check)
- [ ] **Certificate Chain** - Proper signing verification.
- [ ] **TLS Version** - Support for secure protocols (TLS 1.2/1.3).
- [ ] **Cipher Strength** - Detection of weak cryptographic cipsher suites.

## 3. Network & Infrastructure
- [x] **Server Geolocation** (Real via IP-API)
- [x] **ISP/Hosting Provider** (Real via IP-API)
- [ ] **IP Reputation** - Blacklist checks for server IP.
- [ ] **Reverse DNS** - Hostname/IP consistency check.
- [ ] **Port Scanning** - Identifying suspicious open ports (e.g., 22, 3389).

## 4. Reputation & Intelligence
- [x] **Google Safe Browsing** (Implemented, requires API key)
- [ ] **VirusTotal** - Aggregated AV engine results.
- [ ] **PhishTank** - Community-sourced phishing database check.
- [ ] **AbuseIPDB** - Reporting and checking malicious IPs.

## 5. Content & Behavioral Analysis (Sandbox)
- [ ] **Redirect Chain** - Detecting multi-step "jumper" redirects.
- [ ] **JavaScript Analysis** - Monitoring for auto-downloads or obfuscated scripts.
- [ ] **Form Detection** - Flagging fake login/payment fields.
- [ ] **Keyword Analysis** - Searching for high-risk words ("Verify", "Suspended", "Login").
- [ ] **Typosquatting** - Fuzzy-matching domain against popular brands.

## 6. HTTP & Web Security
- [ ] **Security Headers** - Presence of CSP, HSTS, X-Frame-Options.
- [ ] **Cookie Safety** - Secure/HttpOnly flags.
- [ ] **Visual Mimicry** - Favicon/Logo impersonation detection.
