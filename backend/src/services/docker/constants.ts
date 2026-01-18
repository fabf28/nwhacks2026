// Docker configuration
export const DOCKER_SOCKET_PATH = '//./pipe/docker_engine';
export const PLAYWRIGHT_IMAGE = 'mcr.microsoft.com/playwright:v1.49.0-noble';
export const PLAYWRIGHT_VERSION = '1.49.0';

// Suspicious TLDs commonly used for phishing and malware
export const SUSPICIOUS_TLDS = new Set([
  // Free/cheap TLDs often abused
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.work', '.click',
  '.link', '.buzz', '.surf', '.icu', '.monster', '.quest', '.sbs',
  '.rest', '.fit', '.cam', '.loan', '.racing', '.review', '.stream',
  // Country codes often abused
  '.ru', '.cn', '.cc', '.ws', '.pw', '.su',
]);

// Extract TLD from a domain
export function extractTld(domain: string): string {
  const parts = domain.split('.');
  if (parts.length >= 2) {
    return '.' + parts.slice(-1)[0];
  }
  return '';
}

// Keywords commonly found in phishing and scam URLs
export const SUSPICIOUS_KEYWORDS = new Set([
  // Credential harvesting
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
  'secure', 'security', 'account', 'password', 'credential', 'auth',
  'authenticate', 'banking', 'wallet', 'confirm', 'update', 'suspend',
  // Urgency/scam indicators
  'urgent', 'suspended', 'locked', 'limited', 'expire', 'winner',
  'prize', 'congratulation', 'claim', 'gift', 'free', 'bonus', 'reward',
  // Crypto scams
  'crypto', 'bitcoin', 'ethereum', 'airdrop', 'giveaway', 'double',
  'binance', 'coinbase', 'metamask', 'opensea', 'nft',
]);

// Legitimate brand domains for impersonation detection
export const BRAND_DOMAINS = new Map<string, string>([
  ['paypal', 'paypal.com'],
  ['netflix', 'netflix.com'],
  ['amazon', 'amazon.com'],
  ['apple', 'apple.com'],
  ['microsoft', 'microsoft.com'],
  ['google', 'google.com'],
  ['facebook', 'facebook.com'],
  ['instagram', 'instagram.com'],
  ['whatsapp', 'whatsapp.com'],
  ['telegram', 'telegram.org'],
  ['discord', 'discord.com'],
  ['twitter', 'twitter.com'],
  ['linkedin', 'linkedin.com'],
  ['dropbox', 'dropbox.com'],
  ['chase', 'chase.com'],
  ['wellsfargo', 'wellsfargo.com'],
  ['bankofamerica', 'bankofamerica.com'],
]);

// File extensions that may indicate malware downloads
export const SUSPICIOUS_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.msi', '.jar', '.js', '.vbs',
  '.ps1', '.hta', '.apk', '.dmg', '.iso', '.zip', '.rar', '.7z',
  '.dll', '.com', '.pif', '.application', '.gadget', '.wsf', '.inf',
]);

// Known tracking and analytics domains
export const TRACKING_DOMAINS = new Set([
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'facebook.net', 'fbcdn.net', 'analytics.google.com', 'google-analytics.com',
  'hotjar.com', 'mouseflow.com', 'fullstory.com', 'clarity.ms',
  'mixpanel.com', 'segment.io', 'amplitude.com', 'heap.io',
  'crazyegg.com', 'inspectlet.com', 'luckyorange.com',
]);

// Known cryptominer script domains
export const CRYPTOMINER_DOMAINS = new Set([
  'coinhive.com', 'coin-hive.com', 'jsecoin.com', 'cryptoloot.pro',
  'crypto-loot.com', 'miner.pr0gramm.com', 'webmine.pro', 'authedmine.com',
  'ppoi.org', 'projectpoi.com', 'minero.cc', 'reasedoper.pw',
]);

// URL patterns that indicate malicious activity
export const SUSPICIOUS_PATTERNS = [
  /data:text\/html/i,           // Data URI attacks
  /javascript:/i,               // JavaScript protocol
  /base64,[a-z0-9+/]{100,}/i,   // Large base64 payloads
  /eval\s*\(/i,                 // Eval in URLs
  /document\.(cookie|location|write)/i, // DOM manipulation
  /\.php\?.*=[a-f0-9]{32,}/i,   // PHP with hash params (C2)
  /\/wp-(admin|login|includes)/i, // WordPress paths
  /\/\.env/i,                   // Environment file access
  /\/etc\/passwd/i,             // Path traversal
  /\.\.\//,                     // Directory traversal
  /union\s+(all\s+)?select/i,   // SQL injection
  /<script/i,                   // XSS attempts
  /on(error|load|click)\s*=/i,  // Event handler injection
];

// URL length thresholds
export const MAX_QUERY_STRING_LENGTH = 500;
export const MAX_URL_LENGTH = 500;
export const EXTREME_URL_LENGTH = 1000;

