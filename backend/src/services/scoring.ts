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
    safeBrowsing?: {
      isSafe: boolean;
      threats: string[];
    };
    browserScan?: {
      success: boolean;
      containerId?: string;
      pageTitle?: string;
      finalUrl?: string;
      totalRequests: number;
      suspiciousRequests: { url: string; reason?: string }[];
      thirdPartyDomains: string[];
      error?: string;
    };
  };
}

export function calculateScore(result: ScanResult): number {
  let score = 100;

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

  // Safe Browsing scoring (if implemented)
  if (result.checks.safeBrowsing && !result.checks.safeBrowsing.isSafe) {
    score = 0; // Automatic fail if on blacklist
  }

  // Browser network scan scoring
  if (result.checks.browserScan && result.checks.browserScan.success) {
    const suspicious = result.checks.browserScan.suspiciousRequests.length;
    if (suspicious > 0) {
      // Deduct points for suspicious network requests
      score -= Math.min(40, suspicious * 10);
    }
    // Penalize if final URL is on a different domain (redirect to phishing)
    if (result.checks.browserScan.finalUrl) {
      try {
        const originalHost = new URL(result.url).hostname;
        const finalHost = new URL(result.checks.browserScan.finalUrl).hostname;
        if (originalHost !== finalHost) {
          score -= 20;
        }
      } catch {}
    }
    // Penalize excessive third-party domains (potential tracking/malware)
    if (result.checks.browserScan.thirdPartyDomains.length > 20) {
      score -= 10;
    }
  }

  return Math.max(0, Math.min(100, score));
}
