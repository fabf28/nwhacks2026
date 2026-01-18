export interface NetworkRequest {
  url: string;
  domain: string;
  resourceType: string;
  status?: number;
  isSuspicious: boolean;
  reason?: string;
}

export interface DockerScanResult {
  success: boolean;
  containerId?: string;
  pageTitle?: string;
  finalUrl?: string;
  networkRequests: NetworkRequest[];
  suspiciousRequests: NetworkRequest[];
  totalRequests: number;
  thirdPartyDomains: string[];
  error?: string;
}
