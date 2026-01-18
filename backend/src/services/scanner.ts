import { checkWhois } from './whois';
import { checkSsl } from './ssl';
import { checkGeolocation } from './geolocation';
import { checkSafeBrowsing } from './safeBrowsing';
import { calculateScore, ScanResult } from './scoring';

export interface ProgressUpdate {
  step: string;
  message: string;
  status: 'pending' | 'success' | 'warning' | 'error';
  data?: any;
}

export async function scanUrl(
  url: string,
  onProgress: (update: ProgressUpdate) => void,
): Promise<ScanResult> {
  const results: ScanResult = {
    url,
    score: 100,
    checks: {},
  };

  // Step 1: Parse URL
  let hostname: string;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    onProgress({
      step: 'parse',
      message: `Analyzing ${hostname}...`,
      status: 'success',
    });
  } catch (e) {
    onProgress({
      step: 'parse',
      message: 'Invalid URL format',
      status: 'error',
    });
    results.score = 0;
    return results;
  }

  // Step 2: Google Safe Browsing Check (CRITICAL - check first)
  onProgress({
    step: 'safeBrowsing',
    message: 'Checking against threat databases...',
    status: 'pending',
  });

  try {
    const safeBrowsingData = await checkSafeBrowsing(url);
    results.checks.safeBrowsing = safeBrowsingData;

    if (!safeBrowsingData.isSafe) {
      onProgress({
        step: 'safeBrowsing',
        message: `THREAT DETECTED: ${safeBrowsingData.threats.join(', ')}`,
        status: 'error',
        data: safeBrowsingData,
      });
      // Immediately fail the scan if it's on a blacklist
      results.score = 0;
      onProgress({
        step: 'complete',
        message: 'Scan complete. URL is UNSAFE!',
        status: 'error',
        data: results,
      });
      return results;
    } else {
      onProgress({
        step: 'safeBrowsing',
        message: 'No threats detected in Google Safe Browsing',
        status: 'success',
        data: safeBrowsingData,
      });
    }
  } catch (e) {
    onProgress({
      step: 'safeBrowsing',
      message: 'Could not verify against threat databases',
      status: 'warning',
    });
  }

  // Step 3: WHOIS Check
  onProgress({
    step: 'whois',
    message: 'Checking domain registration...',
    status: 'pending',
  });

  try {
    const whoisData = await checkWhois(hostname);
    results.checks.whois = whoisData;

    if (whoisData.ageInDays < 7) {
      onProgress({
        step: 'whois',
        message: `Domain registered ${whoisData.ageInDays} days ago. HIGH RISK!`,
        status: 'error',
        data: whoisData,
      });
    } else if (whoisData.ageInDays < 30) {
      onProgress({
        step: 'whois',
        message: `Domain is ${whoisData.ageInDays} days old. Caution advised.`,
        status: 'warning',
        data: whoisData,
      });
    } else {
      onProgress({
        step: 'whois',
        message: `Domain registered on ${whoisData.createdDate}`,
        status: 'success',
        data: whoisData,
      });
    }
  } catch (e) {
    onProgress({
      step: 'whois',
      message: 'Could not retrieve WHOIS data',
      status: 'warning',
    });
  }

  // Step 3: SSL Check
  onProgress({
    step: 'ssl',
    message: 'Verifying SSL certificate...',
    status: 'pending',
  });

  try {
    const sslData = await checkSsl(hostname);
    results.checks.ssl = sslData;

    if (!sslData.valid) {
      onProgress({
        step: 'ssl',
        message: 'SSL certificate is INVALID or self-signed!',
        status: 'error',
        data: sslData,
      });
    } else {
      onProgress({
        step: 'ssl',
        message: `SSL valid. Issued by ${sslData.issuer}`,
        status: 'success',
        data: sslData,
      });
    }
  } catch (e) {
    onProgress({
      step: 'ssl',
      message: 'Could not verify SSL certificate',
      status: 'warning',
    });
  }

  // Step 4: Geolocation Check
  onProgress({
    step: 'geolocation',
    message: 'Looking up server location...',
    status: 'pending',
  });

  try {
    const geoData = await checkGeolocation(hostname);
    results.checks.geolocation = geoData;

    onProgress({
      step: 'geolocation',
      message: `Server located in ${geoData.city}, ${geoData.country}`,
      status: 'success',
      data: geoData,
    });
  } catch (e) {
    onProgress({
      step: 'geolocation',
      message: 'Could not determine server location',
      status: 'warning',
    });
  }

  // Step 5: Calculate final score
  const finalScore = calculateScore(results);
  results.score = finalScore;

  onProgress({
    step: 'complete',
    message: `Scan complete. Safety Score: ${finalScore}/100`,
    status:
      finalScore >= 70 ? 'success' : finalScore >= 40 ? 'warning' : 'error',
    data: results,
  });

  return results;
}
