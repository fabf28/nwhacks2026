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

  // SSL scoring
  if (result.checks.ssl) {
    if (!result.checks.ssl.valid) {
      score -= 30; // Invalid SSL
    } else if (result.checks.ssl.daysUntilExpiry < 7) {
      score -= 15; // SSL expiring soon
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

  return Math.max(0, Math.min(100, score));
}
