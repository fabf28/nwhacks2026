import Docker from 'dockerode';
import { DOCKER_SOCKET_PATH, PLAYWRIGHT_IMAGE } from './constants';
import {
  generatePlaywrightScript,
  wrapScriptForContainer,
} from './playwrightScript';
import { analyzeAllRequests } from './analyzer';
import type { NetworkRequest, DockerScanResult, SuspiciousRequest } from './types';

/**
 * Parses Docker container logs, stripping the 8-byte frame headers.
 */
function parseDockerLogs(logs: Buffer | string): string {
  const buffer = Buffer.isBuffer(logs) ? logs : Buffer.from(logs);
  let output = '';
  let offset = 0;

  // Docker logs have 8-byte headers for each line
  // Each frame: [STREAM_TYPE(1), 0, 0, 0, SIZE(4), DATA...]
  while (offset < buffer.length) {
    if (offset + 8 > buffer.length) break;
    const size = buffer.readUInt32BE(offset + 4);
    if (offset + 8 + size > buffer.length) break;
    output += buffer.slice(offset + 8, offset + 8 + size).toString('utf8');
    offset += 8 + size;
  }

  // Fallback to simple string conversion if parsing failed
  if (!output.includes('{')) {
    output = buffer
      .toString('utf8')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
  }

  return output;
}

/**
 * Extracts the scan result JSON from container output.
 */
function extractResultJson(output: string): any | null {
  // Find our specific JSON output (starts with {"success":)
  const successJsonMatch = output.match(/\{"success":(true|false).*\}/s);

  if (!successJsonMatch) {
    return null;
  }

  try {
    // Find the complete JSON by matching braces
    let jsonStr = successJsonMatch[0];
    let braceCount = 0;
    let endIndex = 0;

    for (let i = 0; i < jsonStr.length; i++) {
      if (jsonStr[i] === '{') braceCount++;
      if (jsonStr[i] === '}') braceCount--;
      if (braceCount === 0) {
        endIndex = i + 1;
        break;
      }
    }

    jsonStr = jsonStr.substring(0, endIndex);
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

/**
 * Runs a sandboxed browser scan in a Docker container.
 * Visits the URL and captures all network requests for analysis.
 */
export async function runDockerScan(url: string): Promise<DockerScanResult> {
  const docker = new Docker({ socketPath: DOCKER_SOCKET_PATH });

  let originalDomain: string;
  try {
    originalDomain = new URL(url).hostname;
  } catch {
    return {
      success: false,
      networkRequests: [],
      suspiciousRequests: [],
      totalRequests: 0,
      thirdPartyDomains: [],
      error: 'Invalid URL',
    };
  }

  const script = generatePlaywrightScript(url);
  const wrappedScript = wrapScriptForContainer(script);

  try {
    // Pull playwright image if not present
    await new Promise<void>((resolve, reject) => {
      docker.pull(PLAYWRIGHT_IMAGE, (err: any, stream: any) => {
        if (err) return reject(err);
        docker.modem.followProgress(stream, (err: any) => {
          if (err) reject(err);
          else resolve();
        });
      });
    });

    const container = await docker.createContainer({
      Image: PLAYWRIGHT_IMAGE,
      Cmd: ['bash', '-c', wrappedScript],
      HostConfig: {
        AutoRemove: true,
        NetworkMode: 'bridge',
      },
    });

    await container.start();
    const containerId = container.id.substring(0, 12);

    // Wait for container to finish
    await container.wait();

    // Get logs
    const logs = await container.logs({
      stdout: true,
      stderr: true,
      follow: false,
    });

    const output = parseDockerLogs(logs as Buffer);

    // Debug logging
    console.log('[Docker] Raw output length:', (logs as Buffer).length);
    console.log('[Docker] Parsed output:', output.substring(0, 500));

    const result = extractResultJson(output);

    if (result) {
      // Parse raw requests from container
      const rawRequests: NetworkRequest[] = (result.networkRequests || []).map(
        (req: any) => ({
          url: req.url,
          domain: req.domain,
          resourceType: req.resourceType,
          status: req.status,
          isSuspicious: false,
          reason: undefined,
        }),
      );

      // Run enhanced analysis on all requests
      const { analyzedRequests, suspiciousRequests, summary } = analyzeAllRequests(
        rawRequests,
        originalDomain,
      );

      // Map analyzed requests back to NetworkRequest format
      const networkRequests: NetworkRequest[] = analyzedRequests.map((r) => ({
        url: r.url,
        domain: r.domain,
        resourceType: r.resourceType,
        status: r.status,
        isSuspicious: r.analysis.isSuspicious,
        reason: r.analysis.reasons.join('; '),
      }));

      // Map suspicious requests to SuspiciousRequest format
      const suspiciousResult: SuspiciousRequest[] = suspiciousRequests.map((r) => ({
        url: r.url,
        domain: r.domain,
        resourceType: r.resourceType,
        status: r.status,
        isSuspicious: true,
        reason: r.analysis.reasons.join('; '),
        riskLevel: r.analysis.riskLevel,
        categories: r.analysis.categories,
        reasons: r.analysis.reasons,
        riskScore: r.analysis.riskScore,
      }));

      // Extract unique third-party domains
      const thirdPartyDomains = [
        ...new Set(
          rawRequests.map((r) => r.domain).filter((d) => d !== originalDomain),
        ),
      ];

      return {
        success: result.success,
        containerId,
        pageTitle: result.pageTitle,
        finalUrl: result.finalUrl,
        networkRequests,
        suspiciousRequests: suspiciousResult,
        totalRequests: networkRequests.length,
        thirdPartyDomains,
        analysisSummary: summary,
        error: result.error,
      };
    }

    return {
      success: false,
      containerId,
      networkRequests: [],
      suspiciousRequests: [],
      totalRequests: 0,
      thirdPartyDomains: [],
      error: 'Could not parse container output',
    };
  } catch (error) {
    return {
      success: false,
      networkRequests: [],
      suspiciousRequests: [],
      totalRequests: 0,
      thirdPartyDomains: [],
      error: error instanceof Error ? error.message : 'Docker scan failed',
    };
  }
}
