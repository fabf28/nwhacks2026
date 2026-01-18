import { SslResult } from './ssl';
import { SecurityHeadersResult } from './securityHeaders';
import { CookieSecurityResult } from './cookieSecurity';
import { GeolocationResult } from './geolocation';
import { ReverseDnsResult } from './reverseDns';
import { PortScanResult } from './portScan';
import { IpReputationResult } from './ipReputation';
import { SafeBrowsingResult } from './safeBrowsing';
import { SensitiveFileResult } from './sensitiveFiles';
import { VersionDisclosureResult } from './versionDisclosure';
import { AdminPanelResult } from './adminPanels';

export interface ScanResult {
  url: string;
  score: number;
  checks: {
    whois?: {
      createdDate: string;
      ageInDays: number;
      registrar: string;
    };
    ssl?: {
      valid: boolean;
      issuer: string;
      expiresOn: string;
      daysUntilExpiry: number;
    };
    geolocation?: {
      ip: string;
      city: string;
      country: string;
      isp: string;
      org: string;
    };
    safeBrowsing?: {
      isSafe: boolean;
      threats: string[];
    };
    reverseDns?: {
      hostname: string;
      ip: string;
      matches: boolean;
      hostnames: string[];
    };
    portScan?: {
      ip: string;
      openPorts: number[];
      suspiciousPorts: number[];
      isSuspicious: boolean;
    };
    ipReputation?: {
      ip: string;
      abuseConfidenceScore: number;
      isWhitelisted: boolean;
      countryCode: string;
      isp: string;
      domain: string;
      totalReports: number;
      lastReportedAt: string | null;
      isSuspicious: boolean;
    };
    dockerScan?: {
      success: boolean;
      containerId?: string;
      pageTitle?: string;
      finalUrl?: string;
      networkRequests: Array<{
        url: string;
        domain: string;
        resourceType: string;
        status?: number;
        isSuspicious: boolean;
        reason?: string;
      }>;
      suspiciousRequests: Array<{
        url: string;
        domain: string;
        resourceType: string;
        status?: number;
        isSuspicious: boolean;
        reason?: string;
      }>;
      totalRequests: number;
      thirdPartyDomains: string[];
      error?: string;
    };
    ssl?: SslResult;
    geolocation?: GeolocationResult;
    safeBrowsing?: SafeBrowsingResult;
    reverseDns?: ReverseDnsResult;
    portScan?: PortScanResult;
    ipReputation?: IpReputationResult;
    securityHeaders?: SecurityHeadersResult;
    cookieSecurity?: CookieSecurityResult;
    // Vulnerability checks
    sensitiveFiles?: SensitiveFileResult;
    versionDisclosure?: VersionDisclosureResult;
    adminPanels?: AdminPanelResult;
  };
}

export function calculateScore(result: ScanResult): number {
  let score = 100;

  // Safe Browsing scoring (CRITICAL - fail immediately)
  if (result.checks.safeBrowsing && !result.checks.safeBrowsing.isSafe) {
    return 0; // Automatic fail if on blacklist
  }

  // Domain age scoring
  if (result.checks.whois) {
    const age = result.checks.whois.ageInDays;
    if (age < 7) {
      score -= 40; // Very new domain - high risk
    } else if (age < 30) {
      score -= 20; // New domain - medium risk
    } else if (age < 90) {
      score -= 10; // Somewhat new - low risk
    }
  }

  // SSL scoring (enhanced)
  if (result.checks.ssl) {
    const ssl = result.checks.ssl;
    if (!ssl.valid) {
      score -= 30; // Invalid SSL
    } else if (ssl.daysUntilExpiry < 7) {
      score -= 15; // SSL expiring soon
    }

    // Cipher strength scoring
    if (ssl.cipherStrength === 'weak') {
      score -= 20; // Weak cipher
    } else if (ssl.cipherStrength === 'moderate') {
      score -= 5; // Moderate cipher
    }

    // TLS version scoring
    if (ssl.tlsVersion && !ssl.tlsVersion.includes('1.2') && !ssl.tlsVersion.includes('1.3')) {
      score -= 15; // Outdated TLS version
    }
  } else {
    score -= 20; // No SSL data available
  }

  // Reverse DNS scoring
  if (result.checks.reverseDns && !result.checks.reverseDns.matches) {
    score -= 5; // Minor penalty - CDNs often don't match
  }

  // Port scan scoring
  if (result.checks.portScan && result.checks.portScan.isSuspicious) {
    score -= 15; // Suspicious ports open
  }

  // IP Reputation scoring
  if (result.checks.ipReputation) {
    const rep = result.checks.ipReputation;
    if (rep.abuseConfidenceScore > 75) {
      score -= 40; // High abuse score - very suspicious
    } else if (rep.abuseConfidenceScore > 50) {
      score -= 25; // Medium abuse score
    } else if (rep.abuseConfidenceScore > 25) {
      score -= 10; // Low abuse score
    }

    if (rep.totalReports > 100) {
      score -= 15; // Many reports
    } else if (rep.totalReports > 50) {
      score -= 10;
    } else if (rep.totalReports > 10) {
      score -= 5;
    }
  }

  // Docker sandbox scoring
  if (result.checks.dockerScan) {
    const docker = result.checks.dockerScan;
    
    if (!docker.success) {
      score -= 5; // Minor penalty for failed scan
    } else {
      // Penalty based on suspicious requests found
      const suspiciousCount = docker.suspiciousRequests.length;
      if (suspiciousCount > 5) {
        score -= 30; // Many suspicious requests - high risk
      } else if (suspiciousCount > 2) {
        score -= 20; // Some suspicious requests - medium risk
      } else if (suspiciousCount > 0) {
        score -= 10; // Few suspicious requests - low risk
      }

      // Penalty for excessive third-party domains
      const thirdPartyCount = docker.thirdPartyDomains.length;
      if (thirdPartyCount > 20) {
        score -= 10; // Lots of third-party connections
      } else if (thirdPartyCount > 10) {
        score -= 5;
      }
    }
  }

  // Security Headers scoring
  if (result.checks.securityHeaders) {
    const headers = result.checks.securityHeaders;
    if (headers.grade === 'F') {
      score -= 20;
    } else if (headers.grade === 'D') {
      score -= 15;
    } else if (headers.grade === 'C') {
      score -= 10;
    } else if (headers.grade === 'B') {
      score -= 5;
    }
    // Grade A = no penalty
  }

  // Cookie Security scoring
  if (result.checks.cookieSecurity && result.checks.cookieSecurity.hasIssues) {
    const ratio = result.checks.cookieSecurity.secureCookies / result.checks.cookieSecurity.totalCookies;
    if (ratio < 0.5) {
      score -= 10; // Less than half cookies are secure
    } else if (ratio < 1) {
      score -= 5; // Some cookies have issues
    }
  }

  // Vulnerability Scoring - Sensitive Files (CRITICAL)
  if (result.checks.sensitiveFiles && result.checks.sensitiveFiles.hasVulnerabilities) {
    const sf = result.checks.sensitiveFiles;
    score -= sf.criticalCount * 25; // -25 per critical file
    score -= sf.highCount * 15; // -15 per high severity file
    score -= (sf.exposedFiles.length - sf.criticalCount - sf.highCount) * 5; // -5 per medium/low
  }

  // Version Disclosure scoring
  if (result.checks.versionDisclosure && result.checks.versionDisclosure.hasDisclosure) {
    const vd = result.checks.versionDisclosure;
    if (vd.riskLevel === 'high') {
      score -= 15;
    } else if (vd.riskLevel === 'medium') {
      score -= 8;
    } else {
      score -= 3;
    }
  }

  // Admin Panel scoring (informational, minor penalty)
  if (result.checks.adminPanels && result.checks.adminPanels.hasExposedPanels) {
    const adminCount = result.checks.adminPanels.foundPanels.filter(p => p.type === 'admin').length;
    const debugCount = result.checks.adminPanels.foundPanels.filter(p => p.type === 'debug').length;
    score -= debugCount * 10; // Debug endpoints are risky
    score -= adminCount * 3; // Admin panels are common but notable
  }

  return Math.max(0, Math.min(100, score));
}
