import { homedir } from 'os';

// Docker configuration
// macOS Docker Desktop (newer) uses ~/.docker/run/docker.sock
// Linux/older macOS uses /var/run/docker.sock
// Windows uses named pipe
function getDockerSocketPath(): string {
  if (process.platform === 'win32') {
    return '//./pipe/docker_engine';
  }
  // Docker Desktop for macOS location
  const homeSocket = `${homedir()}/.docker/run/docker.sock`;
  return homeSocket;
}

export const DOCKER_SOCKET_PATH = getDockerSocketPath();
export const PLAYWRIGHT_IMAGE = 'mcr.microsoft.com/playwright:v1.49.0-noble';
export const PLAYWRIGHT_VERSION = '1.49.0';

// Known suspicious TLDs commonly used for phishing/malware
export const SUSPICIOUS_TLDS = [
  '.tk',
  '.ml',
  '.ga',
  '.cf',
  '.gq',
  // Removed .xyz, .top, .work, .click, .link, .buzz as they have many legitimate uses
];

// Suspicious URL patterns - ONLY actual malware/phishing indicators
// Be very careful here - overly broad patterns cause false positives
export const SUSPICIOUS_PATTERNS = [
  /malware/i,
  /phish(ing)?/i,
  /keylog(ger)?/i,
  /trojan/i,
  /ransomware/i,
  /crypto.*mine/i,
  /coinhive/i,
  /cryptojack/i,
  /evil/i,
  /\.exe\?/i,  // Executable downloads with query params
  /\.scr\?/i,  // Screensaver (malware vector)
  /powershell/i,
  /cmd\.exe/i,
];

// Known legitimate tracking/analytics domains - don't flag these
export const LEGITIMATE_TRACKING_DOMAINS = [
  'google-analytics.com',
  'googletagmanager.com',
  'googlesyndication.com',
  'googleadservices.com',
  'doubleclick.net',
  'facebook.com',
  'facebook.net',
  'fbcdn.net',
  'twitter.com',
  'linkedin.com',
  'hotjar.com',
  'segment.com',
  'amplitude.com',
  'mixpanel.com',
  'intercom.io',
  'cloudflare.com',
  'cloudflareinsights.com',
  'sentry.io',
  'newrelic.com',
  'datadoghq.com',
  'hubspot.com',
  'bing.com',
  'clarity.ms',
];

// Maximum query string length before flagging as suspicious
export const MAX_QUERY_STRING_LENGTH = 1000;  // Increased from 500

