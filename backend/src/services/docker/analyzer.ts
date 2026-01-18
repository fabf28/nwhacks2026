import {
  SUSPICIOUS_TLDS,
  SUSPICIOUS_PATTERNS,
  MAX_QUERY_STRING_LENGTH,
  LEGITIMATE_TRACKING_DOMAINS,
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

    // Skip if it's a request to the original domain
    if (domain === originalDomain || domain.endsWith(`.${originalDomain}`)) {
      return { isSuspicious: false };
    }

    // Skip if it's a known legitimate tracking/analytics domain
    for (const legitDomain of LEGITIMATE_TRACKING_DOMAINS) {
      if (domain === legitDomain || domain.endsWith(`.${legitDomain}`)) {
        return { isSuspicious: false };
      }
    }

    // Check for suspicious TLDs
    for (const tld of SUSPICIOUS_TLDS) {
      if (domain.endsWith(tld)) {
        return { isSuspicious: true, reason: `Suspicious TLD: ${tld}` };
      }
    }

    // Check for suspicious patterns in URL (only the path, not the domain)
    const pathAndQuery = url.pathname + url.search;
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(pathAndQuery)) {
        return { isSuspicious: true, reason: 'Suspicious pattern in URL' };
      }
    }

    // Check for data exfiltration patterns (very long query strings)
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

