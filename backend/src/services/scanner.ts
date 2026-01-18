import { checkWhois } from './whois';
import { checkSsl } from './ssl';
import { checkGeolocation } from './geolocation';
import { checkSafeBrowsing } from './safeBrowsing';
import { checkReverseDns } from './reverseDns';
import { checkPorts } from './portScan';
import { checkIpReputation } from './ipReputation';
import { runDockerScan } from './docker/docker';
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

  // Step 4: SSL Check
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

  // Step 5: Geolocation Check
  let serverIp = '';
  onProgress({
    step: 'geolocation',
    message: 'Looking up server location...',
    status: 'pending',
  });

  try {
    const geoData = await checkGeolocation(hostname);
    results.checks.geolocation = geoData;
    serverIp = geoData.ip;

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

  // Step 6: Reverse DNS Check
  if (serverIp) {
    onProgress({
      step: 'reverseDns',
      message: 'Verifying reverse DNS records...',
      status: 'pending',
    });

    try {
      const reverseDnsData = await checkReverseDns(hostname, serverIp);
      results.checks.reverseDns = reverseDnsData;

      onProgress({
        step: 'reverseDns',
        message: reverseDnsData.matches
          ? 'Reverse DNS matches hostname'
          : 'Reverse DNS does not match (common for CDNs)',
        status: reverseDnsData.matches ? 'success' : 'warning',
        data: reverseDnsData,
      });
    } catch (e) {
      onProgress({
        step: 'reverseDns',
        message: 'Could not verify reverse DNS',
        status: 'warning',
      });
    }

    // Step 7: Port Scan
    onProgress({
      step: 'portScan',
      message: 'Scanning for open ports...',
      status: 'pending',
    });

    try {
      const portData = await checkPorts(serverIp);
      results.checks.portScan = portData;

      onProgress({
        step: 'portScan',
        message: portData.isSuspicious
          ? `Suspicious ports open: ${portData.suspiciousPorts.join(', ')}`
          : `Standard ports only (${portData.openPorts.length} open)`,
        status: portData.isSuspicious ? 'warning' : 'success',
        data: portData,
      });
    } catch (e) {
      onProgress({
        step: 'portScan',
        message: 'Could not complete port scan',
        status: 'warning',
      });
    }

    // Step 8: IP Reputation Check
    onProgress({
      step: 'ipReputation',
      message: 'Checking IP reputation...',
      status: 'pending',
    });

    try {
      const ipRepData = await checkIpReputation(serverIp);
      results.checks.ipReputation = ipRepData;

      if (ipRepData.isSuspicious) {
        onProgress({
          step: 'ipReputation',
          message: `IP flagged! Abuse score: ${ipRepData.abuseConfidenceScore}%, Reports: ${ipRepData.totalReports}`,
          status: 'error',
          data: ipRepData,
        });
      } else {
        onProgress({
          step: 'ipReputation',
          message: `IP reputation clean (Abuse score: ${ipRepData.abuseConfidenceScore}%)`,
          status: 'success',
          data: ipRepData,
        });
      }
    } catch (e) {
      onProgress({
        step: 'ipReputation',
        message: 'Could not check IP reputation',
        status: 'warning',
      });
    }
  }

  // Step 9: Docker Sandbox Scan (Network Analysis)
  onProgress({
    step: 'dockerScan',
    message: 'Running sandboxed browser analysis...',
    status: 'pending',
  });

  try {
    const dockerData = await runDockerScan(url);
    results.checks.dockerScan = dockerData;

    if (!dockerData.success) {
      onProgress({
        step: 'dockerScan',
        message: `Sandbox scan failed: ${dockerData.error || 'Unknown error'}`,
        status: 'warning',
        data: dockerData,
      });
    } else if (dockerData.suspiciousRequests.length > 0) {
      onProgress({
        step: 'dockerScan',
        message: `Found ${dockerData.suspiciousRequests.length} suspicious network requests`,
        status: 'error',
        data: dockerData,
      });
    } else {
      onProgress({
        step: 'dockerScan',
        message: `Analyzed ${dockerData.totalRequests} network requests. No threats detected.`,
        status: 'success',
        data: dockerData,
      });
    }
  } catch (e) {
    onProgress({
      step: 'dockerScan',
      message: 'Could not run sandbox analysis (is Docker running?)',
      status: 'warning',
    });
  }

  // Final Step: Calculate final score
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
