import {
  SUSPICIOUS_TLDS,
  SUSPICIOUS_PATTERNS,
  MAX_QUERY_STRING_LENGTH,
} from './constants';

export interface AnalysisResult {
  isSuspicious: boolean;
  reason?: string;
}

/**
 * Analyzes a network request URL for suspicious patterns.
 * Checks TLDs, URL patterns, query string length, and IP addresses.
 */
export function analyzeRequest(
  requestUrl: string,
  originalDomain: string,
): AnalysisResult {
  try {
    const url = new URL(requestUrl);
    const domain = url.hostname;

    // Check for suspicious TLDs
    for (const tld of SUSPICIOUS_TLDS) {
      if (domain.endsWith(tld)) {
        return { isSuspicious: true, reason: `Suspicious TLD: ${tld}` };
      }
    }

    // Check for suspicious patterns in URL
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(requestUrl)) {
        return { isSuspicious: true, reason: 'Suspicious pattern in URL' };
      }
    }

    // Check for data exfiltration patterns (long query strings)
    if (url.search.length > MAX_QUERY_STRING_LENGTH) {
      return {
        isSuspicious: true,
        reason: 'Unusually long query string (potential data exfiltration)',
      };
    }

    // Check for IP addresses instead of domains (often suspicious)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      return { isSuspicious: true, reason: 'Direct IP address request' };
    }

    return { isSuspicious: false };
  } catch {
    return { isSuspicious: false };
  }
}
