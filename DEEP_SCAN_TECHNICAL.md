# Deep Scan Technical Deep Dive

This document provides a detailed technical explanation of how VaultScan's Deep Vulnerability Scan works, including the code implementation and legal considerations.

---

## Overview

The Deep Scan adds **3 vulnerability checks** on top of the standard 10 security checks. These are only executed when:

1. User enables the "Deep Vulnerability Scan" toggle
2. User checks the consent box: *"I own this website or have explicit permission"*

```typescript
// backend/src/index.ts
socket.on('start-scan', async (data: { url: string; deepScan?: boolean }) => {
    const deepScan = data.deepScan === true;
    await scanUrl(data.url, onProgress, deepScan);
});
```

---

## Deep Scan Check #1: Sensitive File Exposure

**File:** `backend/src/services/sensitiveFiles.ts`

### What It Does

Probes 27 common paths where developers accidentally expose sensitive files.

### Technical Implementation

```typescript
// List of paths to check
const SENSITIVE_PATHS = [
    { path: '/.env', severity: 'critical', description: 'Environment variables' },
    { path: '/.git/config', severity: 'high', description: 'Git repository' },
    { path: '/backup.sql', severity: 'critical', description: 'Database backup' },
    // ... 24 more paths
];

async function checkFileExists(baseUrl: string, path: string): Promise<boolean> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const response = await fetch(`${baseUrl}${path}`, {
        method: 'HEAD',           // Only fetch headers, not content
        signal: controller.signal,
        redirect: 'manual',       // Don't follow redirects
    });

    clearTimeout(timeout);
    
    // HTTP 200-299 = file exists and is accessible
    return response.status >= 200 && response.status < 300;
}
```

### Paths Checked (27 total)

| Category | Paths | Severity |
|----------|-------|----------|
| **Environment** | `/.env`, `/.env.local`, `/.env.production`, `/.env.backup` | Critical |
| **Git/VCS** | `/.git/config`, `/.git/HEAD`, `/.svn/entries`, `/.hg/requires` | High |
| **Database** | `/backup.sql`, `/dump.sql`, `/database.sql`, `/db.sql` | Critical |
| **Config** | `/wp-config.php`, `/config.php`, `/config.json`, `/config.yml` | High |
| **Secrets** | `/.htpasswd`, `/.htaccess` | Critical/Medium |
| **Debug** | `/phpinfo.php`, `/debug`, `/server-status` | Medium |
| **Logs** | `/error.log`, `/debug.log`, `/access.log` | High/Medium |

### Batched Execution

To avoid overwhelming the target server, requests are batched:

```typescript
const batchSize = 5;
for (let i = 0; i < SENSITIVE_PATHS.length; i += batchSize) {
    const batch = SENSITIVE_PATHS.slice(i, i + batchSize);
    const results = await Promise.all(
        batch.map(file => checkFileExists(baseUrl, file.path))
    );
    // Process results...
}
```

---

## Deep Scan Check #2: Version Disclosure

**File:** `backend/src/services/versionDisclosure.ts`

### What It Does

Extracts server version information from HTTP response headers. This is **completely passive** - just reading headers from a normal request.

### Technical Implementation

```typescript
const VERSION_HEADERS = [
    'server',              // "nginx/1.18.0" or "Apache/2.4.41"
    'x-powered-by',        // "PHP/7.4.3" or "Express"
    'x-aspnet-version',    // ".NET version"
    'x-aspnetmvc-version',
    'x-generator',         // "WordPress 5.8"
    'x-drupal-cache',
];

export async function checkVersionDisclosure(url: string) {
    const response = await fetch(url, { method: 'HEAD' });
    
    const allHeaders: { name: string; value: string }[] = [];
    
    for (const headerName of VERSION_HEADERS) {
        const value = response.headers.get(headerName);
        if (value) {
            allHeaders.push({ name: headerName, value });
            
            // Extract specific versions
            if (headerName === 'x-powered-by' && value.includes('PHP')) {
                phpVersion = extractVersion(value); // "7.4.3"
            }
        }
    }
    
    return { allHeaders, riskLevel: assessRisk(result) };
}
```

### Risk Assessment

```typescript
function assessRisk(result): 'high' | 'medium' | 'low' | 'none' {
    if (result.phpVersion || result.aspNetVersion) {
        return 'high';  // Language versions enable targeted exploits
    }
    if (result.serverVersion && extractVersion(result.serverVersion)) {
        return 'medium'; // Server versions with specific numbers
    }
    return 'low';
}
```

### Why This Matters

Attackers can use version info to find known CVEs:
- `Apache/2.4.49` → CVE-2021-41773 (path traversal)
- `PHP/7.4.3` → Search for vulnerabilities in that version

---

## Deep Scan Check #3: Admin Panel Detection

**File:** `backend/src/services/adminPanels.ts`

### What It Does

Probes common admin, login, and API endpoints to identify exposed management interfaces.

### Technical Implementation

```typescript
const ADMIN_PATHS = [
    { path: '/admin', type: 'admin' },
    { path: '/administrator', type: 'admin' },
    { path: '/login', type: 'login' },
    { path: '/wp-admin', type: 'admin' },
    { path: '/wp-login.php', type: 'login' },
    { path: '/dashboard', type: 'dashboard' },
    { path: '/phpmyadmin', type: 'admin' },
    { path: '/graphql', type: 'api' },
    { path: '/swagger', type: 'api' },
    { path: '/api-docs', type: 'api' },
    { path: '/debug', type: 'debug' },
    { path: '/console', type: 'debug' },
    // ... 7 more paths
];

async function checkPathExists(baseUrl: string, path: string): Promise<boolean> {
    const response = await fetch(`${baseUrl}${path}`, {
        method: 'HEAD',
        redirect: 'manual',
    });
    
    // 200-399 = exists (includes redirects to login pages)
    return response.status >= 200 && response.status < 400;
}
```

### Endpoint Types

| Type | Examples | Risk Level |
|------|----------|------------|
| **admin** | `/admin`, `/wp-admin`, `/phpmyadmin` | Medium |
| **login** | `/login`, `/signin`, `/wp-login.php` | Low (normal) |
| **dashboard** | `/dashboard`, `/panel` | Medium |
| **api** | `/graphql`, `/swagger`, `/api-docs` | Medium |
| **debug** | `/debug`, `/console` | High |

---

## Scoring Impact

All vulnerability findings affect the safety score:

```typescript
// backend/src/services/scoring.ts

// Sensitive Files (most severe)
if (result.checks.sensitiveFiles?.hasVulnerabilities) {
    score -= criticalCount * 25;  // -25 per critical file
    score -= highCount * 15;       // -15 per high severity file
    score -= otherCount * 5;       // -5 per medium/low
}

// Version Disclosure
if (result.checks.versionDisclosure?.hasDisclosure) {
    if (riskLevel === 'high') score -= 15;
    else if (riskLevel === 'medium') score -= 8;
    else score -= 3;
}

// Admin Panels
if (result.checks.adminPanels?.hasExposedPanels) {
    score -= debugCount * 10;  // Debug endpoints are risky
    score -= adminCount * 3;   // Admin panels are notable
}
```

---

## Legal Considerations

### Why Deep Scan Requires Consent

| Check | Legal Status | Reason |
|-------|--------------|--------|
| **Version Disclosure** | ✅ Legal | Passive - just reading headers |
| **Sensitive Files** | ⚠️ Gray Area | Probing unintended paths |
| **Admin Panels** | ⚠️ Gray Area | Probing unintended paths |

### The Legal Issue

**US Computer Fraud and Abuse Act (CFAA):**
> Accessing a computer "without authorization or exceeding authorized access" is a federal crime.

Sending HTTP requests to paths like `/.env` or `/.git/config` could be interpreted as "exceeding authorized access" because:

1. These paths are not linked from the website
2. The owner did not intend them to be accessed
3. You're probing for security weaknesses

### How We Mitigate Legal Risk

```tsx
// frontend/src/components/LinkScanner.tsx
{deepScan && (
    <label>
        <input 
            type="checkbox" 
            checked={hasConsent} 
            onChange={(e) => setHasConsent(e.target.checked)}
        />
        <span style={{ color: 'var(--warning)' }}>
            I own this website or have explicit permission to perform security testing.
        </span>
    </label>
)}
```

**The consent checkbox:**
1. Shifts liability to the user
2. Documents that they claimed authorization
3. Prevents accidental unauthorized scanning

### When Deep Scan IS Legal

| Scenario | Legal? |
|----------|--------|
| Your own websites | ✅ Yes |
| Written penetration test agreement | ✅ Yes |
| Bug bounty programs (in scope) | ✅ Yes |
| Intentionally vulnerable apps (OWASP Juice Shop) | ✅ Yes |
| Random websites without permission | ❌ No |

---

## Network Traffic Summary

### Normal Scan (10 checks)

| Check | Requests | Method |
|-------|----------|--------|
| Safe Browsing | 1 POST | Google API |
| SSL/TLS | 1 TCP | TLS handshake |
| Geolocation | 1 GET | IP-API |
| Reverse DNS | 1 DNS | PTR lookup |
| Port Scan | 10 TCP | Connect attempts |
| IP Reputation | 1 GET | AbuseIPDB API |
| Security Headers | 1 HEAD | Target URL |
| Cookie Security | 1 GET | Target URL |

**Total: ~17 requests**

### Deep Scan (adds 3 checks)

| Check | Requests | Method |
|-------|----------|--------|
| Sensitive Files | 27 HEAD | Target paths |
| Version Disclosure | 1 HEAD | Target URL |
| Admin Panels | 19 HEAD | Target paths |

**Additional: ~47 requests**
**Deep Scan Total: ~64 requests**

---

## Rate Limiting & Safety

To avoid triggering WAFs or being blocked:

1. **Batched requests:** 5 paths at a time
2. **Timeouts:** 3 second timeout per request
3. **HEAD method:** Minimal bandwidth, no body downloaded
4. **No redirects:** `redirect: 'manual'` to avoid loops

```typescript
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 3000);

const response = await fetch(url, {
    method: 'HEAD',
    signal: controller.signal,
    redirect: 'manual',
});
```
