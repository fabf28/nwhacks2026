import { checkWhois } from './whois';
import { checkSsl } from './ssl';
import { calculateScore, ScanResult } from './scoring';
import { runDockerScan } from './docker/docker';

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

  // Step 2: WHOIS Check
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

  // Step 4: Docker Browser Scan
  onProgress({
    step: 'browser',
    message: 'Analyzing page in sandboxed browser...',
    status: 'pending',
  });

  try {
    const browserData = await runDockerScan(url);
    results.checks.browserScan = {
      success: browserData.success,
      containerId: browserData.containerId,
      pageTitle: browserData.pageTitle,
      finalUrl: browserData.finalUrl,
      totalRequests: browserData.totalRequests,
      suspiciousRequests: browserData.suspiciousRequests.map((r) => ({
        url: r.url,
        reason: r.reason,
      })),
      thirdPartyDomains: browserData.thirdPartyDomains,
      error: browserData.error,
    };

    if (browserData.error) {
      onProgress({
        step: 'browser',
        message: `Browser scan failed: ${browserData.error}`,
        status: 'warning',
        data: browserData,
      });
    } else if (browserData.suspiciousRequests.length > 0) {
      onProgress({
        step: 'browser',
        message: `⚠️ Found ${browserData.suspiciousRequests.length} suspicious network requests out of ${browserData.totalRequests} total`,
        status: 'warning',
        data: browserData,
      });
    } else {
      onProgress({
        step: 'browser',
        message: `Page loaded: "${browserData.pageTitle || 'No title'}" - ${browserData.totalRequests} network requests analyzed`,
        status: 'success',
        data: browserData,
      });
    }
  } catch (e) {
    onProgress({
      step: 'browser',
      message: 'Docker scan unavailable',
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
