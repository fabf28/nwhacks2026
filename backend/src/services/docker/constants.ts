// Docker configuration
export const DOCKER_SOCKET_PATH = '//./pipe/docker_engine';
export const PLAYWRIGHT_IMAGE = 'mcr.microsoft.com/playwright:v1.49.0-noble';
export const PLAYWRIGHT_VERSION = '1.49.0';

// Known suspicious TLDs commonly used for phishing/malware
export const SUSPICIOUS_TLDS = [
  '.tk',
  '.ml',
  '.ga',
  '.cf',
  '.gq',
  '.xyz',
  '.top',
  '.work',
  '.click',
  '.link',
  '.buzz',
];

// Suspicious URL patterns that may indicate malware or tracking
export const SUSPICIOUS_PATTERNS = [
  /track(ing|er)?/i,
  /malware/i,
  /phish/i,
  /hack/i,
  /steal/i,
  /crypto.*mine/i,
  /coinhive/i,
];

// Maximum query string length before flagging as suspicious
export const MAX_QUERY_STRING_LENGTH = 500;
