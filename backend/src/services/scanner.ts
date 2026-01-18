import { checkWhois } from './whois';
import { checkSsl } from './ssl';
import { checkGeolocation } from './geolocation';
import { checkSafeBrowsing } from './safeBrowsing';
import { checkReverseDns } from './reverseDns';
import { checkPorts } from './portScan';
import { checkIpReputation } from './ipReputation';
import { checkSecurityHeaders } from './securityHeaders';
import { checkCookieSecurity } from './cookieSecurity';
import { checkSensitiveFiles } from './sensitiveFiles';
import { checkVersionDisclosure } from './versionDisclosure';
import { checkAdminPanels } from './adminPanels';
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
  deepScan: boolean = false,
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

  // Step 9: Security Headers Check
  onProgress({
    step: 'securityHeaders',
    message: 'Checking HTTP security headers...',
    status: 'pending',
  });

  try {
    const headersData = await checkSecurityHeaders(url);
    results.checks.securityHeaders = headersData;

    if (headersData.grade === 'F' || headersData.grade === 'D') {
      onProgress({
        step: 'securityHeaders',
        message: `Security headers: Grade ${headersData.grade} (${headersData.score}/100)`,
        status: 'error',
        data: headersData,
      });
    } else if (headersData.grade === 'C') {
      onProgress({
        step: 'securityHeaders',
        message: `Security headers: Grade ${headersData.grade} (${headersData.score}/100)`,
        status: 'warning',
        data: headersData,
      });
    } else {
      onProgress({
        step: 'securityHeaders',
        message: `Security headers: Grade ${headersData.grade} (${headersData.score}/100)`,
        status: 'success',
        data: headersData,
      });
    }
  } catch (e) {
    onProgress({
      step: 'securityHeaders',
      message: 'Could not check security headers',
      status: 'warning',
    });
  }

  // Step 10: Cookie Security Check
  onProgress({
    step: 'cookieSecurity',
    message: 'Analyzing cookie security...',
    status: 'pending',
  });

  try {
    const cookieData = await checkCookieSecurity(url);
    results.checks.cookieSecurity = cookieData;

    if (cookieData.totalCookies === 0) {
      onProgress({
        step: 'cookieSecurity',
        message: 'No cookies set by server',
        status: 'success',
        data: cookieData,
      });
    } else if (cookieData.hasIssues) {
      onProgress({
        step: 'cookieSecurity',
        message: `${cookieData.secureCookies}/${cookieData.totalCookies} cookies are secure`,
        status: 'warning',
        data: cookieData,
      });
    } else {
      onProgress({
        step: 'cookieSecurity',
        message: `All ${cookieData.totalCookies} cookies are secure`,
        status: 'success',
        data: cookieData,
      });
    }
  } catch (e) {
    onProgress({
      step: 'cookieSecurity',
      message: 'Could not analyze cookies',
      status: 'warning',
    });
  }

  // Deep Scan: Vulnerability Checks (only if enabled)
  if (deepScan) {
    // Step 11: Vulnerability Scanning - Sensitive Files
    onProgress({
      step: 'sensitiveFiles',
      message: 'Scanning for exposed sensitive files...',
      status: 'pending',
    });

    try {
      const sensitiveFilesData = await checkSensitiveFiles(url);
      results.checks.sensitiveFiles = sensitiveFilesData;

      if (sensitiveFilesData.criticalCount > 0) {
        onProgress({
          step: 'sensitiveFiles',
          message: `CRITICAL: ${sensitiveFilesData.criticalCount} sensitive files exposed!`,
          status: 'error',
          data: sensitiveFilesData,
        });
      } else if (sensitiveFilesData.hasVulnerabilities) {
        onProgress({
          step: 'sensitiveFiles',
          message: `Found ${sensitiveFilesData.exposedFiles.length} exposed files`,
          status: 'warning',
          data: sensitiveFilesData,
        });
      } else {
        onProgress({
          step: 'sensitiveFiles',
          message: 'No sensitive files exposed',
          status: 'success',
          data: sensitiveFilesData,
        });
      }
    } catch (e) {
      onProgress({
        step: 'sensitiveFiles',
        message: 'Could not complete file scan',
        status: 'warning',
      });
    }

    // Step 12: Version Disclosure
    onProgress({
      step: 'versionDisclosure',
      message: 'Checking for version disclosure...',
      status: 'pending',
    });

    try {
      const versionData = await checkVersionDisclosure(url);
      results.checks.versionDisclosure = versionData;

      if (versionData.riskLevel === 'high') {
        onProgress({
          step: 'versionDisclosure',
          message: `Version info leaked: ${versionData.poweredBy || versionData.serverVersion}`,
          status: 'error',
          data: versionData,
        });
      } else if (versionData.hasDisclosure) {
        onProgress({
          step: 'versionDisclosure',
          message: `Server: ${versionData.serverVersion || 'Hidden'}`,
          status: 'warning',
          data: versionData,
        });
      } else {
        onProgress({
          step: 'versionDisclosure',
          message: 'No version info disclosed',
          status: 'success',
          data: versionData,
        });
      }
    } catch (e) {
      onProgress({
        step: 'versionDisclosure',
        message: 'Could not check version disclosure',
        status: 'warning',
      });
    }

    // Step 13: Admin Panel Detection
    onProgress({
      step: 'adminPanels',
      message: 'Scanning for exposed admin panels...',
      status: 'pending',
    });

    try {
      const adminData = await checkAdminPanels(url);
      results.checks.adminPanels = adminData;

      if (adminData.hasExposedPanels) {
        const types = [...new Set(adminData.foundPanels.map(p => p.type))];
        onProgress({
          step: 'adminPanels',
          message: `Found ${adminData.foundPanels.length} endpoints (${types.join(', ')})`,
          status: 'warning',
          data: adminData,
        });
      } else {
        onProgress({
          step: 'adminPanels',
          message: 'No exposed admin panels found',
          status: 'success',
          data: adminData,
        });
      }
    } catch (e) {
      onProgress({
        step: 'adminPanels',
        message: 'Could not scan for admin panels',
        status: 'warning',
      });
    }
  } // End of deepScan block

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
