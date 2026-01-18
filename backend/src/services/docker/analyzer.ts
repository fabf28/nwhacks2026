import {
  SUSPICIOUS_TLDS,
  SUSPICIOUS_PATTERNS,
  SUSPICIOUS_KEYWORDS,
  SUSPICIOUS_EXTENSIONS,
  BRAND_DOMAINS,
  TRACKING_DOMAINS,
  CRYPTOMINER_DOMAINS,
  MAX_QUERY_STRING_LENGTH,
  MAX_URL_LENGTH,
  EXTREME_URL_LENGTH,
  extractTld,
} from './constants';
import type { NetworkRequest } from './types';

export interface AnalysisResult {
  isSuspicious: boolean;
  reasons: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  categories: string[];
  riskScore: number;
}

/**
 * Analyzes a network request URL for suspicious patterns.
 */
export function analyzeRequest(
  request: NetworkRequest,
  originalDomain: string,
): AnalysisResult {
  const reasons: string[] = [];
  const categories: Set<string> = new Set();
  let riskScore = 0;

  try {
    const url = new URL(request.url);
    const urlLower = request.url.toLowerCase();
    const domain = url.hostname.toLowerCase();

    // Check for suspicious TLDs
    const tld = extractTld(domain);
    if (SUSPICIOUS_TLDS.has(tld)) {
      reasons.push(`Suspicious TLD: ${tld}`);
      categories.add('suspicious-tld');
      riskScore += 15;
    }

    // Check for direct IP address URLs
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      reasons.push('Direct IP address URL (bypassing DNS)');
      categories.add('ip-based');
      riskScore += 30;
    }

    // Check URL length
    if (urlLower.length > EXTREME_URL_LENGTH) {
      reasons.push(`Extremely long URL (${urlLower.length} chars) - possible obfuscation`);
      categories.add('obfuscation');
      riskScore += 25;
    } else if (urlLower.length > MAX_URL_LENGTH) {
      reasons.push(`Long URL (${urlLower.length} chars)`);
      categories.add('obfuscation');
      riskScore += 10;
    }

    // Check for suspicious keywords
    const urlWords = urlLower.split(/[^a-z0-9]+/);
    const foundKeywords: string[] = [];
    for (const word of urlWords) {
      if (word.length > 2 && SUSPICIOUS_KEYWORDS.has(word) && !originalDomain.includes(word)) {
        foundKeywords.push(word);
      }
    }
    if (foundKeywords.length > 0) {
      reasons.push(`Suspicious keywords: ${[...new Set(foundKeywords)].slice(0, 5).join(', ')}`);
      categories.add('phishing-keywords');
      riskScore += Math.min(foundKeywords.length * 5, 25);
    }

    // Check for suspicious file extensions
    const pathname = url.pathname.toLowerCase();
    for (const ext of SUSPICIOUS_EXTENSIONS) {
      if (pathname.endsWith(ext) || pathname.includes(ext + '?')) {
        reasons.push(`Suspicious file download: ${ext}`);
        categories.add('malware-download');
        riskScore += 35;
        break;
      }
    }

    // Check for malicious URL patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(request.url)) {
        reasons.push(`Suspicious pattern: ${pattern.source.substring(0, 30)}...`);
        categories.add('malicious-pattern');
        riskScore += 30;
        break;
      }
    }

    // Check for excessive URL encoding
    const encodedMatches = request.url.match(/%[0-9A-Fa-f]{2}/g);
    if (encodedMatches && encodedMatches.length > 10) {
      reasons.push(`Heavy URL encoding (${encodedMatches.length} encoded chars)`);
      categories.add('obfuscation');
      riskScore += 20;
    }

    // Check query string length
    if (url.search.length > MAX_QUERY_STRING_LENGTH) {
      reasons.push('Unusually long query string (potential data exfiltration)');
      categories.add('data-exfiltration');
      riskScore += 25;
    }

    // Check for base64 data in query strings
    const base64Match = url.search.match(/[A-Za-z0-9+/]{50,}={0,2}/);
    if (base64Match) {
      reasons.push('Possible data exfiltration (base64 in query)');
      categories.add('data-exfiltration');
      riskScore += 20;
    }

    // Check for internationalized domains (homograph attacks)
    if (/xn--/.test(domain)) {
      reasons.push('Internationalized domain (potential homograph attack)');
      categories.add('homograph');
      riskScore += 25;
    }

    // Check for subdomain abuse
    const subdomainCount = domain.split('.').length - 2;
    if (subdomainCount > 3) {
      reasons.push(`Excessive subdomains (${subdomainCount}) - possible impersonation`);
      categories.add('subdomain-abuse');
      riskScore += 15;
    }

    // Check for brand impersonation
    for (const [brand, legitDomain] of BRAND_DOMAINS) {
      if (domain.includes(brand) && !domain.endsWith(legitDomain)) {
        reasons.push(`Possible ${brand} impersonation`);
        categories.add('brand-impersonation');
        riskScore += 40;
        break;
      }
    }

    // Check for tracking domains
    for (const tracker of TRACKING_DOMAINS) {
      if (domain === tracker || domain.endsWith('.' + tracker)) {
        reasons.push(`Tracking domain: ${tracker}`);
        categories.add('tracking');
        riskScore += 5;
        break;
      }
    }

    // Check for cryptominer domains
    for (const miner of CRYPTOMINER_DOMAINS) {
      if (domain === miner || domain.endsWith('.' + miner)) {
        reasons.push(`Known cryptominer: ${miner}`);
        categories.add('cryptominer');
        riskScore += 50;
        break;
      }
    }

    // Check for sensitive operations over HTTP
    if (url.protocol === 'http:' && foundKeywords.length > 0) {
      reasons.push('Sensitive operation over insecure HTTP');
      categories.add('insecure-http');
      riskScore += 30;
    }

    // Check for cross-origin API calls
    if ((request.resourceType === 'xhr' || request.resourceType === 'fetch') &&
        domain !== originalDomain &&
        !TRACKING_DOMAINS.has(domain)) {
      let isKnownTracker = false;
      for (const tracker of TRACKING_DOMAINS) {
        if (domain.endsWith(tracker)) {
          isKnownTracker = true;
          break;
        }
      }
      if (!isKnownTracker) {
        reasons.push(`Cross-origin API call to: ${domain}`);
        categories.add('cross-origin');
        riskScore += 10;
      }
    }

    // Check for redirects to different domains
    if (request.url !== request.url && request.status && [301, 302, 303, 307, 308].includes(request.status)) {
      if (domain !== originalDomain) {
        reasons.push(`Redirect to different domain: ${domain}`);
        categories.add('redirect');
        riskScore += 15;
      }
    }

  } catch {
    reasons.push('Malformed URL');
    categories.add('malformed');
    riskScore += 10;
  }

  // Calculate risk level based on score
  let riskLevel: 'low' | 'medium' | 'high' | 'critical';
  if (riskScore >= 50) {
    riskLevel = 'critical';
  } else if (riskScore >= 30) {
    riskLevel = 'high';
  } else if (riskScore >= 15) {
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }

  return {
    isSuspicious: riskScore >= 15,
    reasons,
    riskLevel,
    categories: Array.from(categories),
    riskScore,
  };
}

/**
 * Analyzes all network requests and returns a summary.
 */
export function analyzeAllRequests(
  requests: NetworkRequest[],
  originalDomain: string,
): {
  analyzedRequests: (NetworkRequest & { analysis: AnalysisResult })[];
  suspiciousRequests: (NetworkRequest & { analysis: AnalysisResult })[];
  summary: {
    totalRequests: number;
    suspiciousCount: number;
    criticalCount: number;
    highCount: number;
    categories: Record<string, number>;
    overallRisk: 'safe' | 'low' | 'medium' | 'high' | 'critical';
    totalRiskScore: number;
  };
} {
  const analyzedRequests: (NetworkRequest & { analysis: AnalysisResult })[] = [];
  const suspiciousRequests: (NetworkRequest & { analysis: AnalysisResult })[] = [];
  const categoryCounts: Record<string, number> = {};
  let criticalCount = 0;
  let highCount = 0;
  let highestRisk = 0;
  let totalRiskScore = 0;

  for (const request of requests) {
    const analysis = analyzeRequest(request, originalDomain);
    const analyzed = { ...request, analysis };
    analyzedRequests.push(analyzed);

    if (analysis.isSuspicious) {
      suspiciousRequests.push(analyzed);
      totalRiskScore += analysis.riskScore;

      if (analysis.riskLevel === 'critical') criticalCount++;
      if (analysis.riskLevel === 'high') highCount++;

      for (const cat of analysis.categories) {
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      }

      const riskValue = { low: 1, medium: 2, high: 3, critical: 4 }[analysis.riskLevel];
      highestRisk = Math.max(highestRisk, riskValue);
    }
  }

  const overallRisk = (['safe', 'low', 'medium', 'high', 'critical'] as const)[highestRisk];

  return {
    analyzedRequests,
    suspiciousRequests,
    summary: {
      totalRequests: requests.length,
      suspiciousCount: suspiciousRequests.length,
      criticalCount,
      highCount,
      categories: categoryCounts,
      overallRisk,
      totalRiskScore,
    },
  };
}
